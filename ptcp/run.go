package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"sync" // Added for mutex
	"strings" // Added for string manipulation
	"bufio"
)

var pidFile = filepath.Join(os.TempDir(), "ptcp_pids.json")
var socketPath = filepath.Join(os.TempDir(), "ptcp_socket.sock") // Define socket path
var ptcpToPtmSocketPath = filepath.Join(os.TempDir(), "ptcp_to_ptm.sock") // Socket for ptm to connect to ptcp
var ptmSocketPath = filepath.Join(os.TempDir(), "ptm_to_perf.sock") // Socket for perf_tool to connect to ptm
var socketListener net.Listener
var activeConns = make(map[net.Conn]bool)
var activeConnsMutex sync.Mutex

// Stats tracking
var statsMutex sync.Mutex

type roleStats struct {
	LastStats     map[string]uint64
	LastTimeIndex uint64
}

type clientConnectionContext struct {
	Ready         bool
	Client        roleStats
	Server        roleStats
}
var clientConnectionContexts = make(map[net.Conn]*clientConnectionContext)

// handleClientConnection manages a single client connection, reading messages and updating status
func handleClientConnection(c net.Conn) {
	connContext := clientConnectionContexts[c]
	defer func() {
		activeConnsMutex.Lock()
		delete(activeConns, c)
		delete(clientConnectionContexts, c)
		activeConnsMutex.Unlock()
		c.Close()
		fmt.Printf("Closed connection from: %s\n", c.RemoteAddr().String())
	}()

	reader := bufio.NewReader(c)
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			// Error reading or connection closed by client
			return
		}

		//fmt.Printf("Received from client %s: %s\n", c.RemoteAddr().String(), message)
		message = strings.TrimSpace(message)
		if len(message) == 0 {
			continue
		}

		// Process incoming messages from the C client
		switch {
		case strings.HasPrefix(message, "{") && strings.HasSuffix(message, "}"): // Check for JSON
			var rawStats map[string]interface{}
			if err := json.Unmarshal([]byte(message), &rawStats); err != nil {
				fmt.Printf("Error parsing JSON from %s: %v\n", c.RemoteAddr().String(), err)
				continue
			}

			var stats map[string]interface{}
			var responseType string
			if rt, ok := rawStats["response_type"].(string); ok {
				responseType = rt
			}

			var currentRoleStats *roleStats
			roleName := "Unknown"

			if responseType == "AGGREGATED_CLIENT_STATS" {
				stats = rawStats["aggregated_stats"].(map[string]interface{})
				currentRoleStats = &connContext.Client
				roleName = "Client"
			} else if responseType == "AGGREGATED_SERVER_STATS" {
				stats = rawStats["aggregated_stats"].(map[string]interface{})
				currentRoleStats = &connContext.Server
				roleName = "Server"
			} else {
				fmt.Printf("Warning: Unknown response_type '%s' from %s\n", responseType, c.RemoteAddr().String())
				stats = rawStats // Fallback
				currentRoleStats = &roleStats{LastStats: make(map[string]uint64), LastTimeIndex: 0} // Temporary for processing
			}

			// Extract current time_index
			var currentTimeIndex uint64
			if ti, ok := stats["time_index"].(float64); ok {
				currentTimeIndex = uint64(ti)
			}

						statsMutex.Lock() // Protect shared stdout and connContext access

			var statsOutput strings.Builder
			statsOutput.WriteString(fmt.Sprintf("Stats from %s (%s): ", c.RemoteAddr().String(), roleName))

			// Define the keys we consider important
			importantKeys := []string{
				"time_index",               // test time index
				"current_phase",            // current phase name
				"target_connections",       // target connections for client
				"tcp_concurrent",           // current concurrent connections
				"connections_opened",       // total connections opened
				"requests_sent",            // total requests sent
				"success_count",            // total successful ops
				"failure_count",            // total failed ops
				"tcp_bytes_sent",           // total bytes sent
				"tcp_bytes_received",       // total bytes received
			}

			timeDelta := int64(0)
			if currentRoleStats.LastTimeIndex != 0 && currentTimeIndex > currentRoleStats.LastTimeIndex {
				timeDelta = int64(currentTimeIndex - currentRoleStats.LastTimeIndex)
			}

			for _, key := range importantKeys {
				val, ok := stats[key]
				if !ok {
					continue // Skip missing keys
				}
				// Only handle numeric values (JSON numbers are unmarshaled as float64)
				if f, okNum := val.(float64); okNum {
					currentVal := uint64(f)
					previousVal := currentRoleStats.LastStats[key] // Will be 0 if not set

					if currentRoleStats.LastTimeIndex == 0 || timeDelta <= 0 || previousVal == 0 {
						statsOutput.WriteString(fmt.Sprintf("%s:%d ", key, currentVal))
					} else {
						//var valueDelta uint64
						//if currentVal >= previousVal {
						//	valueDelta = currentVal - previousVal
						//} else {
						//	valueDelta = 0
						//}
						//rate := float64(valueDelta) / float64(timeDelta)
						//statsOutput.WriteString(fmt.Sprintf("%s:%d(%.2f/s) ", key, currentVal, rate))
						statsOutput.WriteString(fmt.Sprintf("%s:%d ", key, currentVal))
					}
					currentRoleStats.LastStats[key] = currentVal
				} else {
					statsOutput.WriteString(fmt.Sprintf("%s:%v ", key, val))
				}
			}
			currentRoleStats.LastTimeIndex = currentTimeIndex
			fmt.Println(statsOutput.String())
			statsMutex.Unlock()
		case message == "ready":
			activeConnsMutex.Lock()
			connContext.Ready = true
			activeConnsMutex.Unlock()
			fmt.Printf("Client %s reported ready.\n", c.RemoteAddr().String())
		case message == "not ready":
			activeConnsMutex.Lock()
			connContext.Ready = false
			activeConnsMutex.Unlock()
			fmt.Printf("Client %s reported NOT ready.\n", c.RemoteAddr().String())
		default:
			fmt.Printf("Unknown message from client %s: %s\n", c.RemoteAddr().String(), message)
		}
	}
}

func startSocketServer() error {
	// Clean up any old socket file
	if err := os.Remove(ptcpToPtmSocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error removing old socket file: %w", err)
	}

	var err error
	socketListener, err = net.Listen("unix", ptcpToPtmSocketPath)
	if err != nil {
		return fmt.Errorf("error listening on unix socket: %w", err)
	}
	fmt.Printf("Listening on Unix socket: %s\n", ptcpToPtmSocketPath)

	go func() {
		for {
			conn, err := socketListener.Accept()
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
					fmt.Println("Unix socket listener closed.")
					return
				}
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					fmt.Println("Temporary error accepting connection:", err)
					time.Sleep(time.Second)
					continue
				}
				fmt.Println("Error accepting connection, stopping socket server:", err)
				return
			}

			activeConnsMutex.Lock()
			activeConns[conn] = true
			clientConnectionContexts[conn] = &clientConnectionContext{
				Ready: false,
				Client: roleStats{LastStats: make(map[string]uint64), LastTimeIndex: 0},
				Server: roleStats{LastStats: make(map[string]uint64), LastTimeIndex: 0},
			}
			activeConnsMutex.Unlock()

			fmt.Printf("Accepted connection from: %s\n", conn.RemoteAddr().Network())

			go handleClientConnection(conn) // Start handling the connection
		}
	}()
	return nil
}

func runStartTest() {
	activeConnsMutex.Lock()
	defer activeConnsMutex.Unlock()

	if len(activeConns) == 0 {
		fmt.Println("No perf_tool instances connected to start the test.")
		return
	}

	allReady := true
	for conn := range activeConns {
		if ctx, ok := clientConnectionContexts[conn]; !ok || !ctx.Ready {
			fmt.Printf("ERROR: Client %s is not ready. Please run 'check' first and ensure all instances are ready.\n", conn.RemoteAddr().Network())
			allReady = false
		}
	}

	if !allReady {
		fmt.Println("Test cannot start: Not all perf_tool instances are ready.")
		return
	}

	fmt.Println("All perf_tool instances are ready. Sending 'run' command...")
	message := "run"
	for conn := range activeConns {
		_, err := conn.Write([]byte(message))
		if err != nil {
			fmt.Println("Error writing 'run' to socket:", err)
			conn.Close() // This will trigger the defer in the connection's goroutine to remove it from activeConns
		} else {
			fmt.Printf("Sent '%s' command to %s\n", message, conn.RemoteAddr().Network())
		}
	}
	fmt.Println("Test start command sent to all ready instances.")
}

func stopSocketServer() {
	if socketListener != nil {
		fmt.Println("Closing Unix socket listener...")
		socketListener.Close()
	}
	if err := os.Remove(ptcpToPtmSocketPath); err != nil && !os.IsNotExist(err) {
		fmt.Println("Error removing socket file:", err)
	}
}

func runPrepare(buildDir, configDir string) {
	if err := startSocketServer(); err != nil {
		fmt.Println("Failed to start socket server:", err)
		return
	}

	// Calculate max_clients_clients and max_clients_servers from config
	var maxClientsClients int
	var maxClientsServers int

	// Run server-side components if lb_s.json exists
	lbServerConfig := filepath.Join(configDir, "lb_s.json")
	if _, err := os.Stat(lbServerConfig); err == nil {
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
					maxClientsServers = int(numServers)
				}
			}
		}
	}

	// Run client-side components if lb_c.json exists
	lbClientConfig := filepath.Join(configDir, "lb_c.json")
	if _, err := os.Stat(lbClientConfig); err == nil {
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
					maxClientsClients = int(numClients)
				}
			}
		}
	}

	if maxClientsClients <= 0 {
		maxClientsClients = 10 // Default
	}
	if maxClientsServers <= 0 {
		maxClientsServers = 10 // Default
	}

	var pids []int

	// Start ptm
	ptmPath := filepath.Join(buildDir, "ptm")
	cmdPtm := exec.Command(ptmPath, "--ptcp-socket", ptcpToPtmSocketPath, "--ptm-socket", ptmSocketPath, "--max-clients-clients", fmt.Sprintf("%d", maxClientsClients), "--max-clients-servers", fmt.Sprintf("%d", maxClientsServers))
	cmdPtm.Stdout = os.Stdout
	cmdPtm.Stderr = os.Stderr
	cmdPtm.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmdPtm.Start(); err != nil {
		fmt.Println("Error starting ptm:", err)
		stopSocketServer()
		return
	}
	go cmdPtm.Wait()
	pids = append(pids, cmdPtm.Process.Pid)
	fmt.Printf("Started ptm with PID: %d, max_clients_clients: %d, max_clients_servers: %d\n", cmdPtm.Process.Pid, maxClientsClients, maxClientsServers)

	lbPath := filepath.Join(buildDir, "lb")
	perfToolPath := filepath.Join(buildDir, "perf_tool")

	// Clear the pid file
	if err := os.Remove(pidFile); err != nil && !os.IsNotExist(err) {
		fmt.Println("Error clearing pid file:", err)
	}

	// Run server-side components if lb_s.json exists
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
			go cmdLbS.Wait()
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
						cmdServer := exec.Command(perfToolPath, "server", serverConfig, "--socket-path", ptmSocketPath)
						//cmdServer.Stdout = nil 
						cmdServer.Stdout = os.Stdout
						cmdServer.Stderr = os.Stderr
						cmdServer.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
						if err := cmdServer.Start(); err != nil {
							fmt.Println("Error starting http_server:", err)
						} else {
							pids = append(pids, cmdServer.Process.Pid)
							fmt.Printf("Started http_server_%d with PID: %d\n", i, cmdServer.Process.Pid)
							go cmdServer.Wait()
						}
					}
				}
			}
		}

		fmt.Println("Waiting 1 second before starting clients...")
		time.Sleep(1 * time.Second)
	}

	// Run client-side components if lb_c.json exists
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
			go cmdLbC.Wait()
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
						cmdClient := exec.Command(perfToolPath, "client", clientConfig, "--socket-path", ptmSocketPath)
						//cmdClient.Stdout = nil 
						cmdClient.Stdout = os.Stdout
						cmdClient.Stderr = os.Stderr
						cmdClient.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
						if err := cmdClient.Start(); err != nil {
							fmt.Println("Error starting http_client:", err)
						} else {
							pids = append(pids, cmdClient.Process.Pid)
							fmt.Printf("Started http_client_%d with PID: %d\n", i, cmdClient.Process.Pid)
							go cmdClient.Wait()
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

func runCheck() {
	activeConnsMutex.Lock()
	defer activeConnsMutex.Unlock()

	if len(activeConns) == 0 {
		fmt.Println("No perf_tool instances connected to check.")
		return
	}

	fmt.Println("Checking readiness of perf_tool instances...")
	message := "check"
	allReady := true

	// Reset all client ready statuses before sending check
	for conn := range activeConns {
		if ctx, ok := clientConnectionContexts[conn]; ok {
			ctx.Ready = false
		}
	}

	for conn := range activeConns {
		_, err := conn.Write([]byte(message))
		if err != nil {
			fmt.Printf("Error writing 'check' to %s: %v\n", conn.RemoteAddr().Network(), err)
			conn.Close() // Close connection if writing fails
			allReady = false
		} else {
			fmt.Printf("Sent '%s' command to %s (Network: %s, Addr: %s)\n", message, conn.RemoteAddr(), conn.RemoteAddr().Network(), conn.RemoteAddr().String())
		}
	}
	// This is a synchronous check for now. In a real-world scenario, you might
	// want to wait for responses with a timeout. For simplicity, we're relying
	// on the handleClientConnection goroutines to update clientReadyStatus.
	// We'll give a small delay for responses to come back.
	time.Sleep(2 * time.Second) // Increased sleep for debugging
	fmt.Println("\n--- Readiness Report ---")
	if len(activeConns) == 0 {
		fmt.Println("No perf_tool instances are connected.")
		return
	}

	for conn := range activeConns {
		if ctx, ok := clientConnectionContexts[conn]; ok && ctx.Ready {
			fmt.Printf("Client %s: READY\n", conn.RemoteAddr().Network())
		} else {
			fmt.Printf("Client %s: NOT READY (or status not yet reported)\n", conn.RemoteAddr().Network())
			allReady = false
		}
	}

	if allReady {
		fmt.Println("All connected perf_tool instances are READY.")
	} else {
		fmt.Println("WARNING: Not all connected perf_tool instances are READY.")
	}
}

func runGetStats() {
	activeConnsMutex.Lock()
	defer activeConnsMutex.Unlock()

	if len(activeConns) == 0 {
		fmt.Println("No perf_tool instances connected to get stats from.")
		return
	}

	fmt.Println("Requesting statistics from perf_tool instances...")
	message := "get_stats"

	// Reset any previous stats storage (if we had one)
	// For now, we'll just print them as they come in handleClientConnection

	for conn := range activeConns {
		_, err := conn.Write([]byte(message))
		if err != nil {
			fmt.Printf("Error writing 'get_stats' to %s: %v\n", conn.RemoteAddr().String(), err)
			conn.Close() // Close connection if writing fails
		} else {
			fmt.Printf("Sent '%s' command to %s\n", message, conn.RemoteAddr().String())
		}
	}

	// Wait for a duration to allow clients to respond.
	// In a real-world scenario, we'd use channels to collect responses with a timeout.
	fmt.Println("Waiting for statistics responses (2 seconds)...")
	time.Sleep(2 * time.Second)

	fmt.Println("\n--- Statistics Report (Raw JSON) ---")
	// The actual printing of JSON will happen asynchronously in handleClientConnection
	// This function just triggers the request and waits.
}

func runStop() {
	stopSocketServer() // Call stopSocketServer here

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
				errSig := process.Signal(syscall.Signal(0))
				if errSig == nil {
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

	// Also remove ptm socket
	if err := os.Remove(ptmSocketPath); err != nil && !os.IsNotExist(err) {
		fmt.Println("Error removing ptm socket file:", err)
	}
}
