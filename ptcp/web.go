package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

func startWebServer() {
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/config", handleConfig)
	http.HandleFunc("/run/prepare", handleRunPrepare)
	http.HandleFunc("/run/check", handleRunCheck)
	http.HandleFunc("/run/start", handleRunStart)
	http.HandleFunc("/run/stop", handleRunStop)
	http.HandleFunc("/generate", handleGenerate)
	http.HandleFunc("/state", handleState)
	http.HandleFunc("/stats", handleStats)

	// Serve static files from ptweb/dist
	staticPath := "./ptweb/dist"
	if _, err := os.Stat(staticPath); err == nil {
		fmt.Printf("Serving static files from %s\n", staticPath)
		http.Handle("/", http.FileServer(http.Dir(staticPath)))
	} else {
		fmt.Printf("Warning: Static directory %s not found. Web UI will not be available.\n", staticPath)
	}

	fmt.Println("Starting web server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error starting web server:", err)
	}
}

func handleState(w http.ResponseWriter, r *http.Request) {
	state := getState()
	response := map[string]string{"state": string(state)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}


func handleHealth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "OK")
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	template := r.URL.Query().Get("template")
	if template == "" {
		http.Error(w, "Missing template query parameter", http.StatusBadRequest)
		return
	}

	if template == "list" {
		generateFiles("list", 0, "", 0)
		fmt.Fprintln(w, "Generate command for list issued.")
		return
	}

	countStr := r.URL.Query().Get("count")
	outputDir := r.URL.Query().Get("output_dir")
	numaNodeStr := r.URL.Query().Get("numa_node")

	if countStr == "" || outputDir == "" || numaNodeStr == "" {
		http.Error(w, "Missing count, output_dir, or numa_node query parameter", http.StatusBadRequest)
		return
	}

	count, err := strconv.Atoi(countStr)
	if err != nil {
		http.Error(w, "Invalid count parameter", http.StatusBadRequest)
		return
	}

	numaNode, err := strconv.Atoi(numaNodeStr)
	if err != nil {
		http.Error(w, "Invalid numa_node parameter", http.StatusBadRequest)
		return
	}

	generateFiles(template, count, outputDir, numaNode)
	fmt.Fprintf(w, "Generate command issued for template %s.", template)
}



func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// For now, save to config.json in the current directory
	// In the future, we might want to be more flexible with the path
	err = os.WriteFile("config.json", body, 0644)
	if err != nil {
		http.Error(w, "Error writing config file", http.StatusInternalServerError)
		return
	}

	// Reload config
	if err := json.Unmarshal(body, &config); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	rebuildCommands()

	fmt.Fprintln(w, "Config updated successfully")
}

func handleRunPrepare(w http.ResponseWriter, r *http.Request) {
	buildDir := r.URL.Query().Get("build_dir")
	configDir := r.URL.Query().Get("config_dir")
	if buildDir == "" || configDir == "" {
		http.Error(w, "Missing build_dir or config_dir query parameter", http.StatusBadRequest)
		return
	}
	
	// Running this in a goroutine to not block the HTTP request
	go runPrepare(buildDir, configDir)

	fmt.Fprintln(w, "Prepare command issued.")
}

func handleRunCheck(w http.ResponseWriter, r *http.Request) {
	go runCheck()
	fmt.Fprintln(w, "Check command issued.")
}

func handleRunStart(w http.ResponseWriter, r *http.Request) {
	go runStartTest()
	fmt.Fprintln(w, "Start command issued.")
}

func handleRunStop(w http.ResponseWriter, r *http.Request) {
	go runStop()
	fmt.Fprintln(w, "Stop command issued.")
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	globalStatsMutex.RLock()
	defer globalStatsMutex.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(globalStats); err != nil {
		fmt.Println("Error encoding stats:", err)
	}
}
