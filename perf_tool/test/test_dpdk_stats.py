import json
import os
import subprocess
import time
import requests
import shutil
import threading
import sys
import atexit

# --- Helper Functions (Copied/Adapted from test_web_server.py) ---
def _stream_output(pipe, prefix):
    for line in iter(pipe.readline, ''):
        if line:
            print(f"{prefix} {line.strip()}")
    pipe.close()

def _start_ptcp_web_server(ptcp_path, server_url="http://localhost:8080", health_url="http://localhost:8080/health"):
    print(f"\nStarting ptcp web server at {server_url}...")
    server_process = subprocess.Popen([ptcp_path, "web"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    
    thread = threading.Thread(target=_stream_output, args=(server_process.stdout, "[PTCP]"), daemon=True)
    thread.start()
    
    retries = 10
    for i in range(retries):
        try:
            response = requests.get(health_url, timeout=1) 
            if response.status_code == 200:
                print("PTCP web server is running.")
                return server_process
        except requests.exceptions.ConnectionError:
            print(f"PTCP web server not ready, retry {i+1}/{retries}...")
            time.sleep(1)
        except requests.exceptions.Timeout:
            print(f"PTCP web server health check timed out, retry {i+1}/{retries}...")
            time.sleep(1)
    
    stdout, stderr = server_process.communicate(timeout=5)
    print(f"PTCP server stdout: {stdout.decode()}")
    print(f"PTCP server stderr: {stderr.decode()}")
    server_process.terminate()
    raise Exception("Error: PTCP web server did not start within the timeout period.")

def _stop_ptcp_web_server(server_process):
    print("Stopping ptcp web server...")
    if server_process:
        server_process.terminate()
        try:
            server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_process.kill()
    print("PTCP web server stopped.")

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

def _get_current_ptcp_state(server_url="http://localhost:8080"):
    try:
        response = requests.get(f"{server_url}/state", timeout=1)
        response.raise_for_status()
        return response.json().get("state")
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        # print(f"Error getting ptcp state: {e}") # Suppress frequent errors during polling
        return None

# --- New Helper Functions for this test ---

def _generate_configs(server_url, output_dir, template="both", count=1, numa_node=0):
    print(f"Generating test configurations (template: {template}, count: {count}, numa_node: {numa_node})...")
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)
        
    generate_params = {
        "template": template,
        "count": str(count),
        "output_dir": output_dir,
        "numa_node": str(numa_node)
    }
    response = requests.get(f"{server_url}/generate", params=generate_params)
    assert response.status_code == 200, f"Error calling /generate: {response.status_code} - {response.text}"
    print("Generate command issued successfully.")
    _wait_for_ptcp_state("IDLE", server_url) # Generate should leave it in IDLE

def _start_perf_tool_processes(build_dir, config_dir, server_url):
    print("Running prepare command...")
    prepare_params = {
        "build_dir": build_dir,
        "config_dir": config_dir
    }
    response = requests.post(f"{server_url}/run/prepare", params=prepare_params)
    assert response.status_code == 200, f"Error running prepare: {response.status_code} - {response.text}"
    print("Prepare command issued successfully.")
    _wait_for_ptcp_state("PREPARED", server_url, timeout=60)

    print("Running check command...")
    response = requests.get(f"{server_url}/run/check")
    assert response.status_code == 200, f"Error running check: {response.status_code} - {response.text}"
    print("Check command issued successfully.")
    _wait_for_ptcp_state("CHECKED", server_url, timeout=60)

    print("Running start command...")
    response = requests.get(f"{server_url}/run/start")
    assert response.status_code == 200, f"Error running start: {response.status_code} - {response.text}"
    print("Start command issued successfully.")
    _wait_for_ptcp_state("RUNNING", server_url, timeout=60)

def _stop_perf_tool_processes(server_url):
    print("Running stop command...")
    response = requests.get(f"{server_url}/run/stop")
    assert response.status_code == 200, f"Error running stop: {response.status_code} - {response.text}"
    print("Stop command issued successfully.")
    _wait_for_ptcp_state("STOPPED", server_url, timeout=60)

def _get_aggregated_stats(server_url="http://localhost:8080"):
    print("Requesting aggregated stats from PTCP web server...")
    response = requests.get(f"{server_url}/stats", timeout=5) # Changed endpoint
    response.raise_for_status()
    stats_data = response.json()
    print(f"Received stats: {json.dumps(stats_data, indent=2)}")
    return stats_data

# --- Test Function ---

def test_dpdk_stats_reporting():
    ptcp_path = "./build/ptcp"
    if not os.path.exists(ptcp_path):
        raise FileNotFoundError(f"Error: ptcp executable not found at {ptcp_path}. Please build the project first.")

    server_url = "http://localhost:8080"
    ptcp_process = None
    output_dir = "test_output_dpdk_stats"
    build_dir = "./build"

    # Register cleanup for atexit
    def cleanup_all():
        if ptcp_process:
            _stop_ptcp_web_server(ptcp_process)
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
            print(f"Cleaned up {output_dir}")
        # Kill any remaining processes as a safeguard, using a timeout to avoid hanging
        subprocess.run(["pkill", "ptm"], capture_output=True, timeout=5)
        subprocess.run(["pkill", "lb"], capture_output=True, timeout=5)
        subprocess.run(["pkill", "perf_tool"], capture_output=True, timeout=5)
        print("Ensured all related processes are terminated and directories cleaned.")

    atexit.register(cleanup_all)

    try:
        ptcp_process = _start_ptcp_web_server(ptcp_path, server_url)
        _wait_for_ptcp_state("IDLE", server_url)

        # 1. Generate configs for a client and server
        _generate_configs(server_url, output_dir, template="both", count=1, numa_node=0)

        # 2. Start all perf_tool related processes
        _start_perf_tool_processes(build_dir, output_dir, server_url)
        
        # 3. Allow some time for stats to accumulate
        print("Allowing 5 seconds for DPDK stats to accumulate...")
        time.sleep(5)

        # 4. Get aggregated stats from PTCP
        stats_response = _get_aggregated_stats(server_url)

        # 5. Assert DPDK stats are present and non-zero
        assert "clients" in stats_response, "Expected 'clients' key in stats response"
        assert len(stats_response["clients"]) > 0, "Expected at least one client/server in stats response"
        
        found_dpdk_stats = False
        for client_role_key, client_stats in stats_response["clients"].items():
            print(f"Checking stats for {client_role_key}...")
            if "dpdk_ipackets" in client_stats:
                found_dpdk_stats = True
                assert client_stats["dpdk_ipackets"] > 0, f"DPDK ipackets for {client_role_key} should be greater than 0"
                assert client_stats["dpdk_ibytes"] > 0, f"DPDK ibytes for {client_role_key} should be greater than 0"
                assert client_stats["dpdk_ipackets_rate"] > 0, f"DPDK ipackets_rate for {client_role_key} should be greater than 0"
                assert client_stats["dpdk_ibytes_rate"] > 0, f"DPDK ibytes_rate for {client_role_key} should be greater than 0"
                print(f"DPDK stats for {client_role_key} verified.")
            else:
                print(f"DPDK stats not found for {client_role_key}.")
        
        assert found_dpdk_stats, "No DPDK stats found in any client/server response."

    finally:
        # Cleanup is handled by atexit.register(cleanup_all)
        pass # Explicitly pass, as cleanup is registered

if __name__ == "__main__":
    try:
        test_dpdk_stats_reporting()
        print("\nAll DPDK stats reporting tests passed!")
    except Exception as e:
        print(f"\nDPDK stats reporting test failed: {e}")
        sys.exit(1)

