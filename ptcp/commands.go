package main

import (
	"fmt"
	"os"
	"strconv"
	//"path/filepath"

	//prompt "github.com/c-bata/go-prompt"
)

type Command struct {
	Name        string
	Description string
	Sub         []*Command
	Run         func(args []string)
}

//
// ============================================================
//  STATIC COMMANDS
// ============================================================
//

func initStaticCommands() {
	staticCommands = []*Command{
		{
			Name:        "exit",
			Description: "Exit the application",
			Run: func(args []string) {
				fmt.Println("Bye!")
				os.Exit(0)
			},
		},
		{
			Name:        "save",
			Description: "Manually save JSON to disk",
			Run: func(args []string) {
				saveConfig()
			},
		},
		{
			Name:        "autosave",
			Description: "Enable or disable autosave",
			Run: func(args []string) {
				if len(args) < 1 {
					fmt.Println("Usage: autosave on|off")
					return
				}
				switch args[0] {
				case "on":
					autosave = true
					fmt.Println("Autosave enabled")
				case "off":
					autosave = false
					fmt.Println("Autosave disabled")
				default:
					fmt.Println("Usage: autosave on|off")
				}
			},
		},
		{
			Name:        "add",
			Description: "Add a new top-level key",
			Run: func(args []string) {
				if len(args) < 2 {
					fmt.Println("Usage: add <key> <value>")
					return
				}
				key := args[0]
				val := parseJSONOrPrimitive(args[1])
				config[key] = val
				rebuildCommands()
				maybeAutoSave()
				fmt.Println("Added top-level key:", key)
			},
		},
		{
			Name:        "delete",
			Description: "Delete a top-level key",
			Run: func(args []string) {
				if len(args) < 1 {
					fmt.Println("Usage: delete <key>")
					return
				}
				deleteValue([]string{args[0]})
				fmt.Println("Deleted top-level key:", args[0])
			},
		},
		{
			Name:        "show",
			Description: "Show entire JSON",
			Run: func(args []string) {
				printFullJSON()
			},
		},

		//
		// ============================================================
		//  GENERATE COMMAND
		// ============================================================
		//
		{
			Name:        "generate",
			Description: "Generate configs. Usage: generate <template> <count> <output_dir> <numa_node>",
			Run: func(args []string) {
				if len(args) < 1 {
					fmt.Println("Usage: generate <template> <count> <output_dir> <numa_node>")
					return
				}

				template := args[0]

				// Special case: generate list
				if template == "list" {
					generateFiles("list", 0, "", 0)
					return
				}

				if len(args) < 4 {
					fmt.Println("Usage: generate <template> <count> <output_dir> <numa_node>")
					return
				}

				count, err := strconv.Atoi(args[1])
				if err != nil || count < 1 || count > 128 {
					fmt.Println("Count must be between 1 and 128")
					return
				}

				outputDir := args[2]
				numaNode, err := strconv.Atoi(args[3])
				if err != nil && (numaNode != 0 && numaNode != 1) {
					fmt.Println("numa_node must be between 0 or 1")
					return
				}

				generateFiles(template, count, outputDir, numaNode)
			},
		},
		{
			Name:        "run",
			Description: "Run a test",
			Sub: []*Command{
				{
					Name:        "prepare", // Renamed
					Description: "Prepare a test environment. Usage: run prepare <build_dir> <config_dir>", // Updated description
					Run: func(args []string) {
						if len(args) < 2 {
							fmt.Println("Usage: run prepare <build_dir> <config_dir>") // Updated usage
							return
						}
						buildDir := args[0]
						configDir := args[1]
						runPrepare(buildDir, configDir) // Calls new function
					},
				},
				{
					Name:        "start", // New command
					Description: "Start a prepared test.", // New description
					Run: func(args []string) {
						// No args needed for this one, as it signals already running processes
						runStartTest() // Calls new function
					},
				},
				{
					Name:        "get_stats", // New command
					Description: "Get statistics from all clients/servers.",
					Run: func(args []string) {
						runGetStats() // Calls new function
					},
				},
				{
					Name:        "check", // New command
					Description: "Check if all clients/servers are ready.",
					Run: func(args []string) {
						runCheck() // Calls new function
					},
				},
				{
					Name:        "stop",
					Description: "Stop a test.",
					Run: func(args []string) {
						runStop()
					},
				},
			},
		},
	}
}


