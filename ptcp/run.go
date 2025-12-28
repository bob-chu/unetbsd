package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync" // Added for mutex
	"syscall"
	"time"
)

var pidFile = filepath.Join(os.TempDir(), "ptcp_pids.json")
var socketPath = filepath.Join(os.TempDir(), "ptcp_socket.sock") // Define socket path
var ptcpToPtmSocketPath = filepath.Join(os.TempDir(), "ptcp_to_ptm.sock") // Socket for ptm to connect to ptcp
var ptmSocketPath = filepath.Join(os.TempDir(), "ptm_to_perf.sock") // Socket for perf_tool to connect to ptm
var socketListener net.Listener
var activeConns = make(map[net.Conn]bool)
var activeConnsMutex sync.Mutex

// State management
type State string

const (
	StateIdle       State = "IDLE"
	StatePreparing  State = "PREPARING"
	StatePrepared   State = "PREPARED"
	StateChecking   State = "CHECKING"   // New
	StateChecked    State = "CHECKED"    // New
	StateStarting   State = "STARTING"
	StateRunning    State = "RUNNING"
	StateStopping   State = "STOPPING"
	StateStopped    State = "STOPPED"
	StateError      State = "ERROR"
	StateRunDone    State = "RUN_DONE"   // New
)

var (
	currentState State = StateIdle
	stateMutex   sync.Mutex
)

func setState(newState State) {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	currentState = newState
	fmt.Printf("State changed to: %s\n", currentState)
}

func getState() State {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	return currentState
}

// Stats tracking
var statsMutex sync.Mutex

type roleStats struct {
	LastStats     map[string]uint64
	LastTimeIndex uint64
}

type clientConnectionContext struct {
	Ready  bool
	Client roleStats
	Server roleStats
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
		//fmt.Print(message)
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
				"time_index",
				"current_phase",
				"target_connections",
				"tcp_concurrent",
				"connections_opened",
				"requests_sent",
				"success_count",
				"failure_count",
				"tcp_bytes_sent",
				"tcp_bytes_received",
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
				if f, okNum := val.(float64); okNum {
					currentVal := uint64(f)
					previousVal := currentRoleStats.LastStats[key]

					isRateKey := key == "connections_opened" || key == "requests_sent" || key == "tcp_bytes_sent" || key == "tcp_bytes_received"

					if isRateKey && currentRoleStats.LastTimeIndex != 0 && timeDelta > 0 {
						var valueDelta uint64
						if currentVal >= previousVal {
							valueDelta = currentVal - previousVal
						} else {
							valueDelta = 0
						}
						rate := float64(valueDelta) / float64(timeDelta)

						if key == "tcp_bytes_sent" || key == "tcp_bytes_received" {
							mbps := (rate * 8) / 1000000.0 // Convert bytes/s to Mbps
							statsOutput.WriteString(fmt.Sprintf("%s:%.2fMbps ", key, mbps))
						} else {
							statsOutput.WriteString(fmt.Sprintf("%s:%.2f/s ", key, rate))
						}
					} else {
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
		case message == "done":
			fmt.Println("PTM reported: Test is done.")
			setState(StateRunDone)
		default:
			fmt.Printf("Unknown message from client %s: %s\n", c.RemoteAddr().String(), message)
		}
	}
}

func startSocketServer() error {
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
				Ready:  false,
				Client: roleStats{LastStats: make(map[string]uint64), LastTimeIndex: 0},
				Server: roleStats{LastStats: make(map[string]uint64), LastTimeIndex: 0},
			}
			activeConnsMutex.Unlock()

			fmt.Printf("Accepted connection from: %s\n", conn.RemoteAddr().Network())

			go handleClientConnection(conn)
		}
	}()
	return nil
}

func runStartTest() {
	setState(StateStarting)
	activeConnsMutex.Lock()
	defer activeConnsMutex.Unlock()

	if len(activeConns) == 0 {
		fmt.Println("No perf_tool instances connected to start the test.")
		setState(StateError) // Changed from StatePrepared to StateError
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
		setState(StateError) // Changed from StatePrepared to StateError
		return
	}

	fmt.Println("All perf_tool instances are ready. Sending 'run' command...")
	message := "run"
	for conn := range activeConns {
		_, err := conn.Write([]byte(message))
		if err != nil {
			fmt.Println("Error writing 'run' to socket:", err)
			conn.Close()
			setState(StateError)
			return
		} else {
			fmt.Printf("Sent '%s' command to %s\n", message, conn.RemoteAddr().Network())
		}
	}
	fmt.Println("Test start command sent to all ready instances.")
	setState(StateRunning)
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
	setState(StatePreparing)
	if err := startSocketServer(); err != nil {
		fmt.Println("Failed to start socket server:", err)
		setState(StateError)
		return
	}

	var maxClientsClients int
	var maxClientsServers int

	lbServerConfig := filepath.Join(configDir, "lb_s.json")
	if _, err := os.Stat(lbServerConfig); err == nil {
		data, err := os.ReadFile(lbServerConfig)
		if err != nil {
			fmt.Println("Error reading lb_s.json:", err)
			setState(StateError)
			return
		}
		var lbConfig map[string]interface{}
		if err := json.Unmarshal(data, &lbConfig); err != nil {
			fmt.Println("Error unmarshalling lb_s.json:", err)
			setState(StateError)
			return
		}
		if numServers, ok := lbConfig["num_clients"].(float64); ok {
			maxClientsServers = int(numServers)
		}
	}

	lbClientConfig := filepath.Join(configDir, "lb_c.json")
	if _, err := os.Stat(lbClientConfig); err == nil {
		data, err := os.ReadFile(lbClientConfig)
		if err != nil {
			fmt.Println("Error reading lb_c.json:", err)
			setState(StateError)
			return
		}
		var lbConfig map[string]interface{}
		if err := json.Unmarshal(data, &lbConfig); err != nil {
			fmt.Println("Error unmarshalling lb_c.json:", err)
			setState(StateError)
			return
		}
		if numClients, ok := lbConfig["num_clients"].(float64); ok {
			maxClientsClients = int(numClients)
		}
	}

	if maxClientsClients <= 0 {
		maxClientsClients = 10 // Default
	}
	if maxClientsServers <= 0 {
		maxClientsServers = 10 // Default
	}

	var pids []int

	ptmPath := filepath.Join(buildDir, "ptm")
	cmdPtm := exec.Command(ptmPath, "--ptcp-socket", ptcpToPtmSocketPath, "--ptm-socket", ptmSocketPath, "--max-clients-clients", fmt.Sprintf("%d", maxClientsClients), "--max-clients-servers", fmt.Sprintf("%d", maxClientsServers))
	cmdPtm.Stdout = os.Stdout
	cmdPtm.Stderr = os.Stderr
	cmdPtm.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmdPtm.Start(); err != nil {
		fmt.Println("Error starting ptm:", err)
		stopSocketServer()
		setState(StateError)
		return
	}
	go cmdPtm.Wait()
	pids = append(pids, cmdPtm.Process.Pid)
	fmt.Printf("Started ptm with PID: %d, max_clients_clients: %d, max_clients_servers: %d\n", cmdPtm.Process.Pid, maxClientsClients, maxClientsServers)

	lbPath := filepath.Join(buildDir, "lb")
	perfToolPath := filepath.Join(buildDir, "perf_tool")

	if err := os.Remove(pidFile); err != nil && !os.IsNotExist(err) {
		fmt.Println("Error clearing pid file:", err)
	}

	if _, err := os.Stat(lbServerConfig); err == nil {
		fmt.Println("Starting server-side components...")
		cmdLbS := exec.Command(lbPath, lbServerConfig)
		cmdLbS.Stdout = os.Stdout
		cmdLbS.Stderr = os.Stderr
		cmdLbS.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmdLbS.Start(); err != nil {
			fmt.Println("Error starting lb_s:", err)
			setState(StateError)
			return
		}
		pids = append(pids, cmdLbS.Process.Pid)
		fmt.Printf("Started lb_s with PID: %d\n", cmdLbS.Process.Pid)
		go cmdLbS.Wait()
		time.Sleep(5 * time.Second)
	}

	if _, err := os.Stat(lbClientConfig); err == nil {
		fmt.Println("Starting client-side components...")
		cmdLbC := exec.Command(lbPath, lbClientConfig)
		cmdLbC.Stdout = os.Stdout
		cmdLbC.Stderr = os.Stderr
		cmdLbC.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmdLbC.Start(); err != nil {
			fmt.Println("Error starting lb_c:", err)
			setState(StateError)
			return
		}
		pids = append(pids, cmdLbC.Process.Pid)
		fmt.Printf("Started lb_c with PID: %d\n", cmdLbC.Process.Pid)
		go cmdLbC.Wait()
		time.Sleep(5 * time.Second)
	}

	if _, err := os.Stat(lbServerConfig); err == nil {
		data, err := os.ReadFile(lbServerConfig)
		if err != nil {
			fmt.Println("Error reading lb_s.json:", err)
			setState(StateError)
			return
		}
		var lbConfig map[string]interface{}
		if err := json.Unmarshal(data, &lbConfig); err != nil {
			fmt.Println("Error unmarshalling lb_s.json:", err)
			setState(StateError)
			return
		}
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
					setState(StateError)
					return
				}
				pids = append(pids, cmdServer.Process.Pid)
				fmt.Printf("Started http_server_%d with PID: %d\n", i, cmdServer.Process.Pid)
				go cmdServer.Wait()
			}
		}
		time.Sleep(5 * time.Second)
	}

	if _, err := os.Stat(lbClientConfig); err == nil {
		data, err := os.ReadFile(lbClientConfig)
		if err != nil {
			fmt.Println("Error reading lb_c.json:", err)
			setState(StateError)
			return
		}
		var lbConfig map[string]interface{}
		if err := json.Unmarshal(data, &lbConfig); err != nil {
			fmt.Println("Error unmarshalling lb_c.json:", err)
			setState(StateError)
			return
		}
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
					setState(StateError)
					return
				}
				pids = append(pids, cmdClient.Process.Pid)
				fmt.Printf("Started http_client_%d with PID: %d\n", i, cmdClient.Process.Pid)
				go cmdClient.Wait()
			}
		}
		time.Sleep(5 * time.Second)
	}

	pidData, err := json.Marshal(pids)
	if err != nil {
		fmt.Println("Error marshalling pids:", err)
		setState(StateError)
		return
	}
	if err := os.WriteFile(pidFile, pidData, 0644); err != nil {
		fmt.Println("Error writing pid file:", err)
		setState(StateError)
		return
	}
	setState(StatePrepared)
}

// waitForAllClientsReady polls clientConnectionContexts to confirm all connected clients have reported Ready.
func waitForAllClientsReady(timeout time.Duration, interval time.Duration) bool {
	start := time.Now()
	for time.Since(start) < timeout {
		allReady := true
		// Lock to safely iterate and check clientConnectionContexts
		activeConnsMutex.Lock()
		if len(activeConns) == 0 {
			activeConnsMutex.Unlock()
			return false // No clients to wait for
		}
		for _, ctx := range clientConnectionContexts {
			if !ctx.Ready {
				allReady = false
				break
			}
		}
		activeConnsMutex.Unlock()

		if allReady {
			return true
		}
		time.Sleep(interval)
	}
	return false // Timeout
}

func runCheck() {
	setState(StateChecking)

	// Ensure all clients' Ready status is reset before starting a new check cycle.
	activeConnsMutex.Lock()
	// Capture active connections at the start to iterate safely, as handleClientConnection might modify activeConns
	currentActiveConnsSnapshot := make([]net.Conn, 0, len(activeConns))
	for conn := range activeConns {
		currentActiveConnsSnapshot = append(currentActiveConnsSnapshot, conn)
		if ctx, ok := clientConnectionContexts[conn]; ok {
			ctx.Ready = false
		}
	}
	activeConnsMutex.Unlock() // Unlock after snapshot and resetting Ready flags

	if len(currentActiveConnsSnapshot) == 0 {
		fmt.Println("No perf_tool instances connected to check.")
		setState(StateError)
		return
	}

	fmt.Println("Checking readiness of perf_tool instances...")
	message := "check"
	
	// Send "check" command to all clients in the snapshot.
	for _, conn := range currentActiveConnsSnapshot {
		_, err := conn.Write([]byte(message + "\n")) // Add newline for ReadString
		if err != nil {
			fmt.Printf("Error writing 'check' to %s: %v\n", conn.RemoteAddr().Network(), err)
			// Handle disconnection: handleClientConnection goroutine will clean up.
		} else {
			fmt.Printf("Sent '%s' command to %s (Network: %s, Addr: %s)\n", message, conn.RemoteAddr(), conn.RemoteAddr().Network(), conn.RemoteAddr().String())
		}
	}

	// Wait for all clients to report ready
	if !waitForAllClientsReady(10*time.Second, 500*time.Millisecond) {
		fmt.Println("WARNING: Not all connected perf_tool instances are READY within timeout.")
		setState(StateError)
		return
	}

	// Final check and report
	finalAllReady := true
	activeConnsMutex.Lock() // Lock to safely access activeConns and clientConnectionContexts for final report
	if len(activeConns) == 0 { // Check if clients disconnected during wait
		fmt.Println("No perf_tool instances are connected for final report after waiting.")
		finalAllReady = false
	} else {
		fmt.Println("\n--- Readiness Report ---")
		for conn := range activeConns {
			if ctx, ok := clientConnectionContexts[conn]; ok && ctx.Ready {
				fmt.Printf("Client %s: READY\n", conn.RemoteAddr().Network())
			} else {
				fmt.Printf("Client %s: NOT READY (or status not yet reported)\n", conn.RemoteAddr().Network())
				finalAllReady = false
			}
		}
	}
	activeConnsMutex.Unlock()

	if finalAllReady {
		fmt.Println("All connected perf_tool instances are READY.")
		setState(StateChecked)
	} else {
		fmt.Println("WARNING: Not all connected perf_tool instances are READY. Setting state to ERROR.")
		setState(StateError)
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

	for conn := range activeConns {
		_, err := conn.Write([]byte(message))
		if err != nil {
			fmt.Printf("Error writing 'get_stats' to %s: %v\n", conn.RemoteAddr().String(), err)
			conn.Close()
		} else {
			fmt.Printf("Sent '%s' command to %s\n", message, conn.RemoteAddr().String())
		}
	}

	fmt.Println("Waiting for statistics responses (2 seconds)...")
	time.Sleep(2 * time.Second)

	fmt.Println("\n--- Statistics Report (Raw JSON) ---")
}

func runStop() {
	setState(StateStopping)
	stopSocketServer()

	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No processes to stop.")
		} else {
			fmt.Println("Error reading pid file:", err)
		}
		setState(StateIdle)
		return
	}

	var pids []int
	if err := json.Unmarshal(pidData, &pids); err != nil {
		fmt.Println("Error unmarshalling pids:", err)
		setState(StateError)
		return
	}

	for _, pid := range pids {
		process, err := os.FindProcess(pid)
		if err != nil {
			fmt.Println("Error finding process:", pid, err)
			continue
		}
		fmt.Printf("Sending SIGTERM to process %d for graceful shutdown...\n", pid)
		if err := process.Signal(syscall.SIGTERM); err != nil {
			if err.Error() == "os: process already finished" || strings.Contains(err.Error(), "no such process") {
				fmt.Printf("Process %d already finished or does not exist.\n", pid)
			} else {
				fmt.Printf("Error sending SIGTERM to process %d: %v\n", pid, err)
			}
		}
	}

	fmt.Println("Waiting for 2 seconds...")
	time.Sleep(2 * time.Second)

	for _, pid := range pids {
		process, err := os.FindProcess(pid)
		if err != nil {
			continue
		}

		err = process.Signal(syscall.Signal(0))
		if err == nil {
			fmt.Printf("Process %d did not terminate, forcing kill with SIGKILL...\n", pid)
			if killErr := process.Kill(); killErr != nil {
				if killErr.Error() == "os: process already finished" || strings.Contains(killErr.Error(), "no such process") {
					fmt.Printf("Process %d was killed.\n", pid)
				} else {
					fmt.Printf("Error sending SIGKILL to process %d: %v\n", pid, killErr)
				}
			} else {
				fmt.Printf("Process %d killed.\n", pid)
			}
		}
	}

	fmt.Println("Waiting for all processes to exit...")
	var wg sync.WaitGroup
	for _, pid := range pids {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			process, err := os.FindProcess(p)
			if err != nil {
				return
			}
			for {
				err := process.Signal(syscall.Signal(0))
				if err != nil {
					if err.Error() == "os: process already finished" || strings.Contains(err.Error(), "no such process") {
						fmt.Printf("Process %d has exited.\n", p)
						break
					}
					fmt.Printf("Error checking process %d: %v\n", p, err)
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}(pid)
	}
	wg.Wait()
	fmt.Println("All processes have exited.")

	if err := os.Remove(pidFile); err != nil && !os.IsNotExist(err) {
		fmt.Println("Error clearing pid file:", err)
	}

	if err := os.Remove(ptmSocketPath); err != nil && !os.IsNotExist(err) {
		fmt.Println("Error removing ptm socket file:", err)
	}
	setState(StateStopped)
}
