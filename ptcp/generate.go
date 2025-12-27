package main

import (
    "encoding/json"
    "fmt"
    "net"
    "os"
    "path/filepath"
    "strconv"
    "strings"
)

//
// ============================================================
//  PUBLIC: template names (for list/help if needed)
// ============================================================
//

var GenerateTemplates = []string{
    "http_client",
    "http_server",
    "both",
    "list",
}

//
// ============================================================
//  ENTRY POINT
// ============================================================
//

// generateFiles drives all generation. It expects:
//   template  : "http_client" | "http_server" | "both" | "list"
//   count     : number of clients/servers
//   outputDir : where to write JSON outputs
//   numaNode  : NUMA node index (e.g., 0, 1)
func generateFiles(template string, count int, outputDir string, numaNode int) {
    // Handle "list" without needing NUMA or IPs
    if template == "list" {
        fmt.Println("Available templates:")
        for _, t := range GenerateTemplates {
            fmt.Println(" -", t)
        }
        return
    }

    // Discover CPUs on the NUMA node and make them usable
    cpus, err := getCPUsForNUMANode(numaNode)
    if err != nil {
        fmt.Println("NUMA error:", err)
        return
    }
    usable := usableCPUs(cpus)
    if len(usable) == 0 {
        fmt.Println("No usable CPUs available after reserving first 2 cores")
        return
    }

    switch template {
    	case "http_client":
    		// Need 2 cores for lb_c + count cores for http_client_[id]
    		need := 2 + count
    		if len(usable) < need {
    			fmt.Printf("Not enough CPUs for http_client: need %d, have %d\n", need, len(usable))
    			return
    		}
    		lbCore := usable[0]
    		clientCores := usable[2 : 2+count]
    		generateHttpClientWithCores(count, outputDir, lbCore, clientCores)
    	case "http_server":
    		// Need 2 cores for lb_s + count cores for http_server_[id]
    		need := 2 + count
    		if len(usable) < need {
    			fmt.Printf("Not enough CPUs for http_server: need %d, have %d\n", need, len(usable))
    			return
    		}
    		lbCore := usable[0]
    		serverCores := usable[2 : 2+count]
    		generateHttpServerWithCores(count, outputDir, lbCore, serverCores)
    	case "both":
    		// Order:
    		//   lb_c.core_id (2 cores)
    		//   http_client_[id].dpdk.core_id (count cores)
    		//   lb_s.core_id (2 cores)
    		//   http_server_[id].dpdk.core_id (count cores)
    		need := 2 + count + 2 + count
    		if len(usable) < need {
    			fmt.Printf("Not enough CPUs for both: need %d, have %d\n", need, len(usable))
    			return
    		}
    
    		lbCCore := usable[0]
    		clientCores := usable[2 : 2+count]
    		lbSCore := usable[2+count]
    		serverCores := usable[4+count : 4+2*count]
    
    		generateHttpClientWithCores(count, outputDir, lbCCore, clientCores)
    		generateHttpServerWithCores(count, outputDir, lbSCore, serverCores)
    default:
        fmt.Println("Unknown template:", template)
        fmt.Println("Use: generate list")
    }
}

//
// ============================================================
//  HTTP CLIENT GENERATION (with explicit cores)
// ============================================================
//

func generateHttpClientWithCores(count int, outputDir string, lbCore int, clientCores []int) {
    if err := os.MkdirAll(outputDir, 0755); err != nil {
        fmt.Println("Failed to create output directory:", err)
        return
    }

    ips := expandSrcIPRange()
    if len(ips) == 0 {
        fmt.Println("Invalid or missing IP range at network.l3.src_ip_start / src_ip_end")
        return
    }

    if count > len(ips) {
        fmt.Printf("Requested %d clients but only %d IPs available\n", count, len(ips))
        return
    }

    if len(clientCores) < count {
        fmt.Printf("Not enough client cores: need %d, have %d\n", count, len(clientCores))
        return
    }

    distributed := distributeIPsContiguous(ips, count)

    // lb_c.json with core_id = lbCore
    generateLbC(count, distributed, outputDir, lbCore)

    // Per-client configs
	totalValue, ok := getValue([]string{"objective", "value"}).(float64)
	if !ok {
		fmt.Println("objective.value is not a number")
		return
	}
	baseValue := int(totalValue) / count
	remainder := int(totalValue) % count
    for i := 0; i < count; i++ {
        cfgCopy := deepCopyConfig()
        if cfgCopy == nil {
            fmt.Println("Failed to copy config for client", i)
            return
        }
        setClientIPRange(cfgCopy, distributed[i])
        setDPDKClientCore(cfgCopy, clientCores[i], i)
		value := baseValue
		if i < remainder {
			value++
		}
		setObjectiveValue(cfgCopy, value)

        if netNode, ok := cfgCopy["network"].(map[string]interface{}); ok {
            if l2Node, ok := netNode["l2"].(map[string]interface{}); ok {
                if mac, ok := l2Node["mac_address"].(string); ok {
                    if mac == "00:00:00:00:00:00" {
                        l2Node["mac_address"] = fmt.Sprintf("00:0a:0a:00:00:%02x", i)
                    } else {
                        hw, err := net.ParseMAC(mac)
                        if err == nil {
                            hw[5] = byte(i + 1)
                            l2Node["mac_address"] = hw.String()
                        }
                    }
                }
            }
        }

        filename := filepath.Join(outputDir, fmt.Sprintf("http_client_%d.json", i))
        writeJSON(filename, cfgCopy)
    }

    fmt.Println("Generated http_client configs in", outputDir)
}

//
// ============================================================
//  HTTP SERVER GENERATION (with explicit cores)
// ============================================================
//

func generateHttpServerWithCores(count int, outputDir string, lbCore int, serverCores []int) {
    if err := os.MkdirAll(outputDir, 0755); err != nil {
        fmt.Println("Failed to create output directory:", err)
        return
    }

    ips := expandDstIPRange()
    if len(ips) == 0 {
        fmt.Println("Invalid or missing IP range at network.l3.dst_ip_start / dst_ip_end")
        return
    }

    if count > len(ips) {
        fmt.Printf("Requested %d servers but only %d IPs available\n", count, len(ips))
        return
    }

    if len(serverCores) < count {
        fmt.Printf("Not enough server cores: need %d, have %d\n", count, len(serverCores))
        return
    }

    distributed := distributeIPsContiguous(ips, count)

    // lb_s.json with core_id = lbCore
    generateLbS(count, distributed, outputDir, lbCore)

	totalValue, ok := getValue([]string{"objective", "value"}).(float64)
	if !ok {
		fmt.Println("objective.value is not a number")
		return
	}
	baseValue := int(totalValue) / count
	remainder := int(totalValue) % count
    // Per-server configs
    for i := 0; i < count; i++ {
        cfgCopy := deepCopyConfig()
        if cfgCopy == nil {
            fmt.Println("Failed to copy config for server", i)
            return
        }
        setServerIPRange(cfgCopy, distributed[i])
        setDPDKServerCore(cfgCopy, serverCores[i], i)
		value := baseValue
		if i < remainder {
			value++
		}
		setObjectiveValue(cfgCopy, value)

        if netNode, ok := cfgCopy["network"].(map[string]interface{}); ok {
            if l2Node, ok := netNode["l2"].(map[string]interface{}); ok {
                if mac, ok := l2Node["mac_address"].(string); ok {
                    if mac == "00:00:00:00:00:00" {
                        l2Node["mac_address"] = fmt.Sprintf("02:0a:0a:00:00:%02x", i)
                    } else {
                        hw, err := net.ParseMAC(mac)
                        if err == nil {
                            hw[5] = byte(i + 1)
                            l2Node["mac_address"] = hw.String()
                        }
                    }
                }
            }
        }

        filename := filepath.Join(outputDir, fmt.Sprintf("http_server_%d.json", i))
        writeJSON(filename, cfgCopy)
    }

    fmt.Println("Generated http_server configs in", outputDir)
}

//
// ============================================================
//  IP RANGE EXPANSION
// ============================================================
//

func expandSrcIPRange() []string {
    return expandIPRangeGeneric("src_ip_start", "src_ip_end")
}

func expandDstIPRange() []string {
    return expandIPRangeGeneric("dst_ip_start", "dst_ip_end")
}

func expandIPRangeGeneric(startKey, endKey string) []string {
    startVal := getValue([]string{"network", "l3", startKey})
    endVal := getValue([]string{"network", "l3", endKey})

    startStr, ok1 := startVal.(string)
    endStr, ok2 := endVal.(string)
    if !ok1 || !ok2 {
        return nil
    }

    startIP := net.ParseIP(startStr).To4()
    endIP := net.ParseIP(endStr).To4()
    if startIP == nil || endIP == nil {
        return nil
    }

    if ipGreater(startIP, endIP) {
        return nil
    }

    var ips []string
    cur := make(net.IP, len(startIP))
    copy(cur, startIP)

    for {
        ips = append(ips, cur.String())
        if ipEqual(cur, endIP) {
            break
        }
        incIP(cur)
    }

    return ips
}

func ipGreater(a, b net.IP) bool {
    for i := 0; i < 4; i++ {
        if a[i] > b[i] {
            return true
        }
        if a[i] < b[i] {
            return false
        }
    }
    return false
}

func ipEqual(a, b net.IP) bool {
    for i := 0; i < 4; i++ {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

func incIP(ip net.IP) {
    for i := 3; i >= 0; i-- {
        ip[i]++
        if ip[i] != 0 {
            break
        }
    }
}

//
// ============================================================
//  CONTIGUOUS IP DISTRIBUTION
// ============================================================
//

func distributeIPsContiguous(ips []string, count int) [][]string {
    result := make([][]string, count)

    total := len(ips)
    base := total / count
    extra := total % count

    start := 0
    for i := 0; i < count; i++ {
        size := base
        if i < extra {
            size++
        }
        end := start + size
        result[i] = append([]string{}, ips[start:end]...)
        start = end
    }

    return result
}

//
// ============================================================
//  LB FILE GENERATION (with core_id from NUMA)
// ============================================================
//

func generateLbC(count int, distributed [][]string, outputDir string, coreID int) {
    clients := make([]map[string]interface{}, count)

    for i := 0; i < count; i++ {
        clients[i] = map[string]interface{}{
            "id":  i,
            "ips": distributed[i],
        }
    }

    clientDpdkArgs := getValue([]string{"dpdk_client", "args"}).(string)

    lb := map[string]interface{}{
        "dpdk_args":   clientDpdkArgs,
        "core_id":     coreID,
        "num_clients": count,
        "clients":     clients,
    }

    filename := filepath.Join(outputDir, "lb_c.json")
    writeJSON(filename, lb)
}

func generateLbS(count int, distributed [][]string, outputDir string, coreID int) {
    clients := make([]map[string]interface{}, count)

    for i := 0; i < count; i++ {
        clients[i] = map[string]interface{}{
            "id":  i,
            "ips": distributed[i],
        }
    }

    serverDpdkArgs := getValue([]string{"dpdk_server", "args"}).(string)

    lb := map[string]interface{}{
        "dpdk_args":   serverDpdkArgs,
        "core_id":     coreID,
        "num_clients": count,
        "clients":     clients,
    }

    filename := filepath.Join(outputDir, "lb_s.json")
    writeJSON(filename, lb)
}

//
// ============================================================
//  CONFIG CLONING + RANGE / CORE INJECTION
// ============================================================
//

func deepCopyConfig() map[string]interface{} {
    data, err := json.Marshal(config)
    if err != nil {
        fmt.Println("Failed to marshal config:", err)
        return nil
    }

    var out map[string]interface{}
    if err := json.Unmarshal(data, &out); err != nil {
        fmt.Println("Failed to unmarshal config:", err)
        return nil
    }
    return out
}

func setClientIPRange(cfg map[string]interface{}, ips []string) {
    if len(ips) == 0 {
        return
    }

    netNode, ok := cfg["network"].(map[string]interface{})
    if !ok {
        fmt.Println("Config missing 'network' object")
        return
    }

    l3Node, ok := netNode["l3"].(map[string]interface{})
    if !ok {
        fmt.Println("Config missing 'network.l3' object")
        return
    }

    l3Node["src_ip_start"] = ips[0]
    l3Node["src_ip_end"] = ips[len(ips)-1]
}

func setServerIPRange(cfg map[string]interface{}, ips []string) {
    if len(ips) == 0 {
        return
    }

    netNode, ok := cfg["network"].(map[string]interface{})
    if !ok {
        fmt.Println("Config missing 'network' object")
        return
    }

    l3Node, ok := netNode["l3"].(map[string]interface{})
    if !ok {
        fmt.Println("Config missing 'network.l3' object")
        return
    }

    l3Node["dst_ip_start"] = ips[0]
    l3Node["dst_ip_end"] = ips[len(ips)-1]
}

// Set dpdk.core_id in the cloned config
func setDPDKCore(cfg map[string]interface{}, core int) {
    dpdkNode, ok := cfg["dpdk"].(map[string]interface{})
    if !ok {
        fmt.Println("Config missing 'dpdk' object")
        return
    }
    dpdkNode["core_id"] = core
}

func setDPDKClientCore(cfg map[string]interface{}, core int, index int) {
    dpdkNode, ok := cfg["dpdk_client"].(map[string]interface{})
    if !ok {
        fmt.Println("Config missing 'dpdk_client' object")
        return
    }
    dpdkNode["core_id"] = core
    dpdkNode["client_ring_idx"] = index 
}

func setDPDKServerCore(cfg map[string]interface{}, core int, index int) {
    dpdkNode, ok := cfg["dpdk_server"].(map[string]interface{})
    if !ok {
        fmt.Println("Config missing 'dpdk_server' object")
        return
    }
    dpdkNode["core_id"] = core
    dpdkNode["client_ring_idx"] = index 
}

func setObjectiveValue(cfg map[string]interface{}, value int) {
	objectiveNode, ok := cfg["objective"].(map[string]interface{})
	if !ok {
		fmt.Println("Config missing 'objective' object")
		return
	}
	objectiveNode["value"] = value
}
//
// ============================================================
//  NUMA CPU DISCOVERY
// ============================================================
//

// getCPUsForNUMANode reads /sys/devices/system/node/node<id>/cpulist
// and returns all CPU IDs for that NUMA node.
func getCPUsForNUMANode(numa int) ([]int, error) {
    path := fmt.Sprintf("/sys/devices/system/node/node%d/cpulist", numa)
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read %s: %v", path, err)
    }

    text := strings.TrimSpace(string(data))
    if text == "" {
        return nil, fmt.Errorf("empty cpulist for NUMA node %d", numa)
    }

    parts := strings.Split(text, ",")
    var cpus []int

    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p == "" {
            continue
        }

        if strings.Contains(p, "-") {
            bounds := strings.SplitN(p, "-", 2)
            start, err1 := strconv.Atoi(bounds[0])
            end, err2 := strconv.Atoi(bounds[1])
            if err1 != nil || err2 != nil || end < start {
                continue
            }
            for i := start; i <= end; i++ {
                cpus = append(cpus, i)
            }
        } else {
            v, err := strconv.Atoi(p)
            if err != nil {
                continue
            }
            cpus = append(cpus, v)
        }
    }

    if len(cpus) == 0 {
        return nil, fmt.Errorf("no CPUs parsed for NUMA node %d", numa)
    }

    return cpus, nil
}

// usableCPUs drops the first 2 cores (reserved for OS).
func usableCPUs(cpus []int) []int {
    if len(cpus) <= 2 {
        return []int{}
    }
    return cpus[2:]
}

//
// ============================================================
//  JSON WRITER
// ============================================================
//

func writeJSON(filename string, obj interface{}) {
    data, err := json.MarshalIndent(obj, "", "  ")
    if err != nil {
        fmt.Println("Failed to marshal JSON:", err)
        return
    }
    if err := os.WriteFile(filename, data, 0644); err != nil {
        fmt.Println("Failed to write file:", filename, "error:", err)
    }
}
