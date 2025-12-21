package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

var pidFile = filepath.Join(os.TempDir(), "ptcp_pids.json")

func runStart(buildDir, configDir string) {
	var pids []int
	lbPath := filepath.Join(buildDir, "lb")
	perfToolPath := filepath.Join(buildDir, "perf_tool")

	// Clear the pid file
	if err := os.Remove(pidFile); err != nil && !os.IsNotExist(err) {
		fmt.Println("Error clearing pid file:", err)
	}

	// Run server-side components if lb_s.json exists
	lbServerConfig := filepath.Join(configDir, "lb_s.json")
	if _, err := os.Stat(lbServerConfig); err == nil {
		fmt.Println("Starting server-side components...")

		// Run lb_s
		cmdLbS := exec.Command(lbPath, lbServerConfig)
		cmdLbS.Stdout = os.Stdout
		cmdLbS.Stderr = os.Stderr
		cmdLbS.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmdLbS.Start(); err != nil {
			fmt.Println("Error starting lb_s:", err)
		} else {
			pids = append(pids, cmdLbS.Process.Pid)
			fmt.Printf("Started lb_s with PID: %d\n", cmdLbS.Process.Pid)
		}

		// Read num_clients from lb_s.json
		data, err := os.ReadFile(lbServerConfig)
		if err != nil {
			fmt.Println("Error reading lb_s.json:", err)
		} else {
			var lbConfig map[string]interface{}
			if err := json.Unmarshal(data, &lbConfig); err != nil {
				fmt.Println("Error unmarshalling lb_s.json:", err)
			} else {
				if numServers, ok := lbConfig["num_clients"].(float64); ok {
					for i := 0; i < int(numServers); i++ {
						serverConfig := filepath.Join(configDir, fmt.Sprintf("http_server_%d.json", i))
						cmdServer := exec.Command(perfToolPath, "server", serverConfig)
						cmdServer.Stdout = os.Stdout
						cmdServer.Stderr = os.Stderr
						cmdServer.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
						if err := cmdServer.Start(); err != nil {
							fmt.Println("Error starting http_server:", err)
						} else {
							pids = append(pids, cmdServer.Process.Pid)
							fmt.Printf("Started http_server_%d with PID: %d\n", i, cmdServer.Process.Pid)
						}
					}
				}
			}
		}

		fmt.Println("Waiting 1 second before starting clients...")
		time.Sleep(1 * time.Second)
	}

	// Run client-side components if lb_c.json exists
	lbClientConfig := filepath.Join(configDir, "lb_c.json")
	if _, err := os.Stat(lbClientConfig); err == nil {
		fmt.Println("Starting client-side components...")

		// Run lb_c
		cmdLbC := exec.Command(lbPath, lbClientConfig)
		cmdLbC.Stdout = os.Stdout
		cmdLbC.Stderr = os.Stderr
		cmdLbC.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmdLbC.Start(); err != nil {
			fmt.Println("Error starting lb_c:", err)
		} else {
			pids = append(pids, cmdLbC.Process.Pid)
			fmt.Printf("Started lb_c with PID: %d\n", cmdLbC.Process.Pid)
		}

		// Read num_clients from lb_c.json
		data, err := os.ReadFile(lbClientConfig)
		if err != nil {
			fmt.Println("Error reading lb_c.json:", err)
		} else {
			var lbConfig map[string]interface{}
			if err := json.Unmarshal(data, &lbConfig); err != nil {
				fmt.Println("Error unmarshalling lb_c.json:", err)
			} else {
				if numClients, ok := lbConfig["num_clients"].(float64); ok {
					for i := 0; i < int(numClients); i++ {
						clientConfig := filepath.Join(configDir, fmt.Sprintf("http_client_%d.json", i))
						cmdClient := exec.Command(perfToolPath, "client", clientConfig)
						cmdClient.Stdout = os.Stdout
						cmdClient.Stderr = os.Stderr
						cmdClient.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
						if err := cmdClient.Start(); err != nil {
							fmt.Println("Error starting http_client:", err)
						} else {
							pids = append(pids, cmdClient.Process.Pid)
							fmt.Printf("Started http_client_%d with PID: %d\n", i, cmdClient.Process.Pid)
						}
					}
				}
			}
		}
	}

	// Save pids to file
	pidData, err := json.Marshal(pids)
	if err != nil {
		fmt.Println("Error marshalling pids:", err)
	} else {
		if err := os.WriteFile(pidFile, pidData, 0644); err != nil {
			fmt.Println("Error writing pid file:", err)
		}
	}
}

func runStop() {
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No processes to stop.")
		} else {
			fmt.Println("Error reading pid file:", err)
		}
		return
	}

	var pids []int
	if err := json.Unmarshal(pidData, &pids); err != nil {
		fmt.Println("Error unmarshalling pids:", err)
		return
	}

	for _, pid := range pids {
		process, err := os.FindProcess(pid)
		if err != nil {
			fmt.Println("Error finding process:", pid, err)
			continue
		}
		if err := process.Kill(); err != nil {
			// On Unix, Process.Kill always returns an error.
			// We can check if the process is still alive.
			if err.Error() != "os: process already finished" {
				// To check if process is still running, we send signal 0
				err_sig := process.Signal(syscall.Signal(0))
				if err_sig == nil {
					fmt.Println("Error killing process:", pid, err)
				} else {
					fmt.Println("Process", pid, "killed.")
				}
			} else {
				fmt.Println("Process", pid, "already finished.")
			}
		} else {
			fmt.Println("Process", pid, "killed.")
		}
	}

	// Clear the pid file
	if err := os.Remove(pidFile); err != nil && !os.IsNotExist(err) {
		fmt.Println("Error clearing pid file:", err)
	}
}
