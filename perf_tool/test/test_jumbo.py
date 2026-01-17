import json
import os
import subprocess
import time
import requests
import shutil
import threading
import sys

def _stream_output(pipe, prefix):
    for line in iter(pipe.readline, ''):
        if line:
            print(f"{prefix} {line.strip()}")
    pipe.close()

def _start_server(ptcp_path, server_url="http://localhost:8080", health_url="http://localhost:8080/health"):
    print(f"\nStarting ptcp web server at {server_url}...")
    # Redirect stdout to a pipe so we can stream it
    server_process = subprocess.Popen([ptcp_path, "web"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    
    # Start a thread to stream the output
    thread = threading.Thread(target=_stream_output, args=(server_process.stdout, "[PTCP]"), daemon=True)
    thread.start()
    
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
    if stderr:
        print(f"Server stderr: {stderr.decode()}")
    server_process.terminate()
    raise Exception("Error: Server did not start within the timeout period.")

def _stop_server(server_process, server_url="http://localhost:8080", output_dir=None):
    print("Stopping ptcp web server...")
    try:
        requests.get(f"{server_url}/run/stop", timeout=2)
    except:
        pass
    
    if server_process:
        server_process.terminate()
        try:
            server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_process.kill()
    
    # Kill any remaining processes as a safeguard
    subprocess.run(["pkill", "ptm"], capture_output=True)
    subprocess.run(["pkill", "lb"], capture_output=True)
    subprocess.run(["pkill", "perf_tool"], capture_output=True)

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

def _wait_for_ptcp_state(expected_state, server_url="http://localhost:8080", timeout=60, interval=0.5):
    start_time = time.time()
    while time.time() - start_time < timeout:
        current_state = _get_current_ptcp_state(server_url)
        if current_state == expected_state:
            print(f"PTCP state reached '{expected_state}'.")
            return True
        if current_state == "ERROR":
            raise RuntimeError(f"PTCP entered ERROR state while waiting for '{expected_state}'.")
        print(f"Waiting for PTCP state '{expected_state}', current state: '{current_state}'...")
        time.sleep(interval)
    raise TimeoutError(f"Timed out waiting for PTCP state to become '{expected_state}'. Last state: '{current_state}'")

def test_full_scenario_jumbo_frames():
    ptcp_path = "./build/ptcp"
    if not os.path.exists(ptcp_path):
        raise FileNotFoundError(f"Error: ptcp executable not found at {ptcp_path}. Please build the project first.")

    server_url = "http://localhost:8080"
    server_process = None
    output_dir = "test_jumbo_output"
    try:
        server_process = _start_server(ptcp_path, server_url)

        _wait_for_ptcp_state("IDLE", server_url)

        # 1. Load base config
        config_file_path = "ptcp/config.json"
        if not os.path.exists(config_file_path):
            raise FileNotFoundError(f"Error: Config file not found at {config_file_path}")
        
        with open(config_file_path, 'r') as f:
            sample_config = json.load(f)
        
        print("Loading base config.json to the server...")
        response = requests.post(f"{server_url}/config", data=json.dumps(sample_config))
        assert response.status_code == 200, f"Error loading config: {response.status_code} - {response.text}"
        _wait_for_ptcp_state("IDLE", server_url)

        # 2. Generate test configs
        print("Generating test configurations...")
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
        _wait_for_ptcp_state("IDLE", server_url)

        # 3. Modify the generated server config for Jumbo Frames
        server_config_path = os.path.join(output_dir, "lb_s.json")
        assert os.path.exists(server_config_path), f"Server config {server_config_path} not found."

        with open(server_config_path, 'r') as f:
            server_config = json.load(f)
        
        # Set the MTU for the interface
        #server_config["dpdk_args"] = server_config.get("dpdk_args", "") + " --eth-dev-mtu=9000"

        with open(server_config_path, 'w') as f:
            json.dump(server_config, f, indent=4)
        print(f"Modified {server_config_path} to set MTU to 9000.")

        # Also modify the client config for Jumbo Frames
        client_config_path = os.path.join(output_dir, "lb_c.json")
        assert os.path.exists(client_config_path), f"Client config {client_config_path} not found."

        with open(client_config_path, 'r') as f:
            client_config = json.load(f)

        #client_config["dpdk_args"] = client_config.get("dpdk_args", "") + " --eth-dev-mtu=9000"

        with open(client_config_path, 'w') as f:
            json.dump(client_config, f, indent=4)
        print(f"Modified {client_config_path} to set MTU to 9000.")


        # 4. Prepare
        print("Running prepare command...")
        prepare_params = {
            "build_dir": "./build",
            "config_dir": output_dir
        }
        response = requests.post(f"{server_url}/run/prepare", params=prepare_params)
        assert response.status_code == 200, f"Error running prepare: {response.status_code} - {response.text}"
        _wait_for_ptcp_state("PREPARED", server_url, timeout=60)

        # 5. Check
        print("Running check command...")
        response = requests.get(f"{server_url}/run/check")
        assert response.status_code == 200, f"Error running check: {response.status_code} - {response.text}"
        _wait_for_ptcp_state("CHECKED", server_url, timeout=60)

        # 6. Start
        print("Starting Jumbo Frame test...")
        response = requests.get(f"{server_url}/run/start")
        assert response.status_code == 200, f"Error running start: {response.status_code} - {response.text}"
        _wait_for_ptcp_state("RUNNING", server_url, timeout=60)
        
        # Wait for completion
        print("Waiting for test to complete...")
        _wait_for_ptcp_state("RUN_DONE", server_url, timeout=120)
        print("Jumbo Frame test completed successfully!")

    finally:
        _stop_server(server_process, server_url, output_dir)

if __name__ == "__main__":
    try:
        print("Running: test_full_scenario_jumbo_frames")
        test_full_scenario_jumbo_frames()
        print("\nAll tests passed!")
    except Exception as e:
        print(f"\nTests failed: {e}")
        # Make sure to stop the server even on failure
        # This part is tricky because server_process might not be defined
        # _stop_server is now responsible for all cleanup
        subprocess.run(["pkill", "-9", "ptcp"], capture_output=True)
        subprocess.run(["pkill", "-9", "ptm"], capture_output=True)
        subprocess.run(["pkill", "-9", "lb"], capture_output=True)
        subprocess.run(["pkill", "-9", "perf_tool"], capture_output=True)
        sys.exit(1)
