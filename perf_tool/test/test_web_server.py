import json
import os
import subprocess
import time
import requests
import shutil

def _start_server(ptcp_path, server_url="http://localhost:8080", health_url="http://localhost:8080/health"):
    print(f"\nStarting ptcp web server at {server_url}...")
    # Redirect stdout and stderr to pipes so we can capture them if needed
    #server_process = subprocess.Popen([ptcp_path, "web"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    server_process = subprocess.Popen([ptcp_path, "web"], stdout=None, stderr=None)
    
    retries = 10
    for i in range(retries):
        try:
            # Add a timeout to the request to prevent hanging
            response = requests.get(health_url, timeout=1) 
            if response.status_code == 200:
                print("Server is running.")
                return server_process
        except requests.exceptions.ConnectionError:
            print(f"Server not ready, retry {i+1}/{retries}...")
            time.sleep(1)
        except requests.exceptions.Timeout:
            print(f"Server health check timed out, retry {i+1}/{retries}...")
            time.sleep(1)
    
    # If server failed to start, print captured output before raising an exception
    stdout, stderr = server_process.communicate(timeout=5)
    print(f"Server stdout: {stdout.decode()}")
    print(f"Server stderr: {stderr.decode()}")
    server_process.terminate()
    raise Exception("Error: Server did not start within the timeout period.")

def _stop_server(server_process, output_dir=None):
    print("Stopping ptcp web server...")
    server_process.terminate()
    server_process.wait()
    print("Server stopped.")
    if output_dir and os.path.exists(output_dir):
        shutil.rmtree(output_dir)
        print(f"Cleaned up {output_dir}")

def _get_current_ptcp_state(server_url="http://localhost:8080"):
    try:
        response = requests.get(f"{server_url}/state", timeout=1)
        response.raise_for_status() # Raise an exception for HTTP errors
        return response.json().get("state")
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"Error getting ptcp state: {e}")
        return None

def _wait_for_ptcp_state(expected_state, server_url="http://localhost:8080", timeout=30, interval=0.5):
    start_time = time.time()
    while time.time() - start_time < timeout:
        current_state = _get_current_ptcp_state(server_url)
        if current_state == expected_state:
            print(f"PTCP state reached '{expected_state}'.")
            return True
        print(f"Waiting for PTCP state '{expected_state}', current state: '{current_state}'...")
        time.sleep(interval)
    raise TimeoutError(f"Timed out waiting for PTCP state to become '{expected_state}'. Last state: '{current_state}'")

def test_basic_web_server_endpoints():
    ptcp_path = "./build/ptcp"
    if not os.path.exists(ptcp_path):
        raise FileNotFoundError(f"Error: ptcp executable not found at {ptcp_path}. Please build the project first.")

    server_url = "http://localhost:8080"
    server_process = None
    output_dir = "test_output_basic" # Unique output dir for this test
    try:
        server_process = _start_server(ptcp_path, server_url)

        # Ensure server is in IDLE state initially
        _wait_for_ptcp_state("IDLE", server_url)

        # 1. Load config
        config_file_path = "ptcp/config.json"
        if not os.path.exists(config_file_path):
            raise FileNotFoundError(f"Error: Config file not found at {config_file_path}")
        
        with open(config_file_path, 'r') as f:
            sample_config = json.load(f)
        
        print("Loading config.json to the server...")
        response = requests.post(f"{server_url}/config", data=json.dumps(sample_config))
        assert response.status_code == 200, f"Error loading config: {response.status_code} - {response.text}"
        assert response.text.strip() == "Config updated successfully", f"Unexpected config response: {response.text}"
        print("Config loaded successfully.")
        # After config load, state should remain IDLE or return to IDLE
        _wait_for_ptcp_state("IDLE", server_url)

        # 2. Test the generate endpoint
        print("Testing /generate endpoint (both 2 0)...")
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)
            
        generate_params = {
            "template": "both",
            "count": "2",
            "output_dir": output_dir,
            "numa_node": "0"
        }
        response = requests.get(f"{server_url}/generate", params=generate_params)
        assert response.status_code == 200, f"Error calling /generate: {response.status_code} - {response.text}"
        print("Generate command issued successfully.")
        # After generate, state should remain IDLE
        _wait_for_ptcp_state("IDLE", server_url)

        # Check if files are created
        expected_files = [
                "lb_c.json", "http_client_0.json", "http_client_1.json",
                "lb_s.json", "http_server_0.json", "http_server_1.json",
                ]
        for f in expected_files:
            assert os.path.exists(os.path.join(output_dir, f)), f"Expected file {f} was not generated."
        print("All expected files generated successfully.")

    finally:
        _stop_server(server_process, output_dir)


def test_full_scenario_web_server():
    ptcp_path = "./build/ptcp"
    if not os.path.exists(ptcp_path):
        raise FileNotFoundError(f"Error: ptcp executable not found at {ptcp_path}. Please build the project first.")

    server_url = "http://localhost:8080"
    server_process = None
    output_dir = "test_output_full_scenario" # Unique output dir for this test
    try:
        server_process = _start_server(ptcp_path, server_url)

        # Ensure server is in IDLE state initially
        _wait_for_ptcp_state("IDLE", server_url)

        # 1. Load config
        config_file_path = "ptcp/config.json"
        if not os.path.exists(config_file_path):
            raise FileNotFoundError(f"Error: Config file not found at {config_file_path}")
        
        with open(config_file_path, 'r') as f:
            sample_config = json.load(f)
        
        print("Loading config.json to the server...")
        response = requests.post(f"{server_url}/config", data=json.dumps(sample_config))
        assert response.status_code == 200, f"Error loading config: {response.status_code} - {response.text}"
        assert response.text.strip() == "Config updated successfully", f"Unexpected config response: {response.text}"
        print("Config loaded successfully.")
        # After config load, state should remain IDLE
        _wait_for_ptcp_state("IDLE", server_url)

        # 2. Generate both 1 0
        print("Generating test configurations (both 1 0)...")
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)
            
        generate_params = {
            "template": "both",
            "count": "1",
            "output_dir": output_dir,
            "numa_node": "0"
        }
        response = requests.get(f"{server_url}/generate", params=generate_params)
        assert response.status_code == 200, f"Error calling /generate: {response.status_code} - {response.text}"
        print("Generate command issued successfully.")
        # After generate, state should remain IDLE
        _wait_for_ptcp_state("IDLE", server_url)

        # Verify generated files
        expected_files = ["lb_c.json", "http_client_0.json", "lb_s.json", "http_server_0.json"]
        for f in expected_files:
            assert os.path.exists(os.path.join(output_dir, f)), f"Expected file {f} was not generated."
        print("All expected files generated successfully.")

        # 3. Run prepare build_dir config_dir
        print("Running prepare command...")
        prepare_params = {
            "build_dir": "./build",
            "config_dir": output_dir # Use the generated config directory
        }
        response = requests.post(f"{server_url}/run/prepare", params=prepare_params)
        assert response.status_code == 200, f"Error running prepare: {response.status_code} - {response.text}"
        print("Prepare command issued successfully.")
        _wait_for_ptcp_state("PREPARED", server_url, timeout=60) # Increased timeout for prepare

        # 4. Run check
        print("Running check command...")
        response = requests.get(f"{server_url}/run/check")
        assert response.status_code == 200, f"Error running check: {response.status_code} - {response.text}"
        print("Check command issued successfully.")
        _wait_for_ptcp_state("CHECKED", server_url, timeout=60)

        # 5. Run start
        print("Running start command...")
        response = requests.get(f"{server_url}/run/start")
        assert response.status_code == 200, f"Error running start: {response.status_code} - {response.text}"
        print("Start command issued successfully.")
        _wait_for_ptcp_state("RUNNING", server_url, timeout=60) # Wait for test to start
        _wait_for_ptcp_state("RUN_DONE", server_url, timeout=120) # Wait for test execution to complete (from PTM)

        # 6. Run stop
        print("Running stop command...")
        response = requests.get(f"{server_url}/run/stop")
        assert response.status_code == 200, f"Error running stop: {response.status_code} - {response.text}"
        print("Stop command issued successfully.")
        _wait_for_ptcp_state("STOPPED", server_url, timeout=60) # Wait for complete shutdown

    finally:
        _stop_server(server_process, output_dir)
