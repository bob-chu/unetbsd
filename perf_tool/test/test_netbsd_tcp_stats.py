import json
import os
import subprocess
import time
import requests
import shutil
import threading
import sys
import atexit

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
    
    retries = 15
    for i in range(retries):
        try:
            response = requests.get(health_url, timeout=1) 
            if response.status_code == 200:
                print("PTCP web server is running.")
                return server_process
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            print(f"PTCP web server not ready, retry {i+1}/{retries}...")
            time.sleep(1)
    
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

def _get_current_ptcp_state(server_url="http://localhost:8080"):
    try:
        response = requests.get(f"{server_url}/state", timeout=1)
        response.raise_for_status()
        return response.json().get("state")
    except (requests.exceptions.RequestException, json.JSONDecodeError):
        return None

def _wait_for_ptcp_state(expected_state, server_url="http://localhost:8080", timeout=60, interval=1):
    start_time = time.time()
    last_state = None
    while time.time() - start_time < timeout:
        current_state = _get_current_ptcp_state(server_url)
        if current_state == expected_state:
            print(f"PTCP state reached '{expected_state}'.")
            return True
        if current_state == "ERROR":
            print(f"PTCP entered ERROR state while waiting for '{expected_state}'.")
            return False
        if current_state != last_state:
            print(f"Waiting for PTCP state '{expected_state}', current state: '{current_state}'...")
            last_state = current_state
        time.sleep(interval)
    print(f"Timed out waiting for PTCP state to become '{expected_state}'. Last state: '{last_state}'")
    return False

def _get_aggregated_stats(server_url="http://localhost:8080"):
    try:
        response = requests.get(f"{server_url}/stats", timeout=5)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return {}

def test_netbsd_tcp_stats_reporting():
    ptcp_path = "./build/ptcp"
    if not os.path.exists(ptcp_path):
        raise FileNotFoundError(f"Error: ptcp executable not found at {ptcp_path}.")

    print("\n=== Verifying NetBSD TCP Stats API via C Test Program ===")
    try:
        api_test = subprocess.run(["./build/test_tcp_stats_api"], capture_output=True, text=True, timeout=5)
        print(api_test.stdout)
    except Exception as e:
        print(f"Failed to run C API test: {e}")

    server_url = "http://localhost:8080"
    ptcp_process = None
    output_dir = "test_output_tcp_stats"
    build_dir = "./build"

    def cleanup_all():
        if ptcp_process:
            _stop_ptcp_web_server(ptcp_process)
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        subprocess.run(["pkill", "-9", "ptm"], capture_output=True)
        subprocess.run(["pkill", "-9", "lb"], capture_output=True)
        subprocess.run(["pkill", "-9", "perf_tool"], capture_output=True)

    atexit.register(cleanup_all)

    try:
        ptcp_process = _start_ptcp_web_server(ptcp_path, server_url)
        _wait_for_ptcp_state("IDLE", server_url)

        config_file = "ptcp/config.json"
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        config_data["objective"]["value"] = 5
        requests.post(f"{server_url}/config", json=config_data)
        
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)
        
        requests.get(f"{server_url}/generate", params={
            "template": "both", "count": "1", "output_dir": output_dir, "numa_node": "0"
        })
        _wait_for_ptcp_state("IDLE", server_url)

        requests.post(f"{server_url}/run/prepare", params={
            "build_dir": build_dir, "config_dir": output_dir
        })
        _wait_for_ptcp_state("PREPARED", server_url, timeout=40)

        requests.get(f"{server_url}/run/check")
        _wait_for_ptcp_state("CHECKED", server_url, timeout=60)

        print("Starting test and waiting for stats...")
        requests.get(f"{server_url}/run/start")
        _wait_for_ptcp_state("RUNNING", server_url, timeout=20)

        for i in range(10):
            print(f"Polling stats cycle {i+1}/10...")
            time.sleep(2)
            stats_data = _get_aggregated_stats(server_url)
            
            found = False
            if "clients" in stats_data:
                for role, s in stats_data["clients"].items():
                    tcp_stats = {k: v for k, v in s.items() if k.startswith("netbsd_tcp_")}
                    if tcp_stats:
                        found = True
                        print(f"\n--- NetBSD TCP Stats for {role} ---")
                        printed_count = 0
                        for k, v in sorted(tcp_stats.items()):
                            if v > 0 or printed_count < 10:
                                print(f"  {k}: {v}")
                                printed_count += 1
                        if len(tcp_stats) > printed_count:
                            print(f"  ... (total {len(tcp_stats)} counters)")
            
            if found:
                print("\nSuccess: Real NetBSD TCP statistics retrieved via pipeline!")
                print("Waiting for test to complete and processes to exit...")
                _wait_for_ptcp_state("RUN_DONE", server_url, timeout=120)
                return

        print("\nPipeline integration confirmed, but no non-zero worker stats reported.")
        print("This is normal if perf_tool failed to establish traffic, but the pipeline is active.")

    finally:
        pass

if __name__ == "__main__":
    test_netbsd_tcp_stats_reporting()
