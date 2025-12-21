package main

import (
    "encoding/json"
    "fmt"
    "net"
    "os"
    "path/filepath"
)

//
// ============================================================
//  PUBLIC: template names for auto-completion
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

func generateFiles(template string, count int, outputDir string, numaNode int) {
    switch template {

    case "list":
        fmt.Println("Available templates:")
        for _, t := range GenerateTemplates {
            fmt.Println(" -", t)
        }
        return

    case "http_client":
        generateHttpClientFiles(count, outputDir)
        return

    case "http_server":
        generateHttpServerFiles(count, outputDir)
        return

    case "both":
        generateHttpClientFiles(count, outputDir)
        generateHttpServerFiles(count, outputDir)
        return

    default:
        fmt.Println("Unknown template:", template)
        fmt.Println("Use: generate list")
        return
    }
}

//
// ============================================================
//  HTTP CLIENT GENERATION
// ============================================================
//

func generateHttpClientFiles(count int, outputDir string) {
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

    distributed := distributeIPsContiguous(ips, count)

    generateLbC(count, distributed, outputDir)

    for i := 0; i < count; i++ {
        cfgCopy := deepCopyConfig()
        setClientIPRange(cfgCopy, distributed[i])
        filename := filepath.Join(outputDir, fmt.Sprintf("http_client_%d.json", i))
        writeJSON(filename, cfgCopy)
    }

    fmt.Println("Generated http_client configs in", outputDir)
}

//
// ============================================================
//  HTTP SERVER GENERATION
// ============================================================
//

func generateHttpServerFiles(count int, outputDir string) {
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

    distributed := distributeIPsContiguous(ips, count)

    generateLbS(count, distributed, outputDir)

    for i := 0; i < count; i++ {
        cfgCopy := deepCopyConfig()
        setServerIPRange(cfgCopy, distributed[i])
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
//  LB FILE GENERATION
// ============================================================
//

func generateLbC(count int, distributed [][]string, outputDir string) {
    clients := make([]map[string]interface{}, count)

    for i := 0; i < count; i++ {
        clients[i] = map[string]interface{}{
            "id":  i,
            "ips": distributed[i],
        }
    }

    lb := map[string]interface{}{
        "dpdk_args":   "--vdev=net_memif,id=0,role=client --proc-type=primary --file-prefix=memif_c",
        "core_id":     4,
        "num_clients": count,
        "clients":     clients,
    }

    filename := filepath.Join(outputDir, "lb_c.json")
    writeJSON(filename, lb)
}

func generateLbS(count int, distributed [][]string, outputDir string) {
    clients := make([]map[string]interface{}, count)

    for i := 0; i < count; i++ {
        clients[i] = map[string]interface{}{
            "id":  i,
            "ips": distributed[i],
        }
    }

    lb := map[string]interface{}{
        "dpdk_args":   "--vdev=net_memif,id=0,role=server --proc-type=primary --file-prefix=memif_s",
        "core_id":     4,
        "num_clients": count,
        "clients":     clients,
    }

    filename := filepath.Join(outputDir, "lb_s.json")
    writeJSON(filename, lb)
}

//
// ============================================================
//  CONFIG CLONING + RANGE INJECTION
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

    netNode := cfg["network"].(map[string]interface{})
    l3Node := netNode["l3"].(map[string]interface{})

    l3Node["src_ip_start"] = ips[0]
    l3Node["src_ip_end"] = ips[len(ips)-1]
}

func setServerIPRange(cfg map[string]interface{}, ips []string) {
    if len(ips) == 0 {
        return
    }

    netNode := cfg["network"].(map[string]interface{})
    l3Node := netNode["l3"].(map[string]interface{})

    l3Node["dst_ip_start"] = ips[0]
    l3Node["dst_ip_end"] = ips[len(ips)-1]
}

//
// ============================================================
//  JSON WRITER
// ============================================================
//

func writeJSON(filename string, obj interface{}) {
    data, _ := json.MarshalIndent(obj, "", "  ")
    os.WriteFile(filename, data, 0644)
}

func getCPUsForNUMANode(numa int) ([]int, error) {
    path := fmt.Sprintf("/sys/devices/system/node/node%d/cpulist", numa)
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read %s: %v", path, err)
    }

    text := strings.TrimSpace(string(data))
    parts := strings.Split(text, ",")

    var cpus []int

    for _, p := range parts {
        if strings.Contains(p, "-") {
            bounds := strings.Split(p, "-")
            start, _ := strconv.Atoi(bounds[0])
            end, _ := strconv.Atoi(bounds[1])
            for i := start; i <= end; i++ {
                cpus = append(cpus, i)
            }
        } else {
            v, _ := strconv.Atoi(p)
            cpus = append(cpus, v)
        }
    }

    return cpus, nil
}

func usableCPUs(cpus []int) []int {
    if len(cpus) <= 2 {
        return []int{}
    }
    return cpus[2:]
}

func assignCPUs(cpuList []int, need int) ([]int, error) {
    if len(cpuList) < need {
        return nil, fmt.Errorf("not enough CPUs: need %d, have %d", need, len(cpuList))
    }
    return cpuList[:need], nil
}
