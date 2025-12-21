package main

import (
	"encoding/json"
	"fmt"
	"os"

	prompt "github.com/c-bata/go-prompt"
)

var (
	config       map[string]interface{}
	configPath   string
	rootCommands []*Command
	staticCommands []*Command
	autosave     = false
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./ptcp <config.json>")
		return
	}

	configPath = os.Args[1]

	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Println("Failed to read config:", err)
		return
	}

	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Println("Invalid JSON:", err)
		return
	}

	initStaticCommands()
	rebuildCommands()

	fmt.Println("Interactive JSON CLI")
	fmt.Println("Loaded:", configPath)
	fmt.Println("Type commands or press TAB for suggestions")

	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix(">>> "),
	)
	p.Run()
}
