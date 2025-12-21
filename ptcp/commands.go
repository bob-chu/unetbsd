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
					Name:        "start",
					Description: "Start a test. Usage: run start <build_dir> <config_dir>",
					Run: func(args []string) {
						if len(args) < 2 {
							fmt.Println("Usage: run start <build_dir> <config_dir>")
							return
						}
						buildDir := args[0]
						configDir := args[1]
						runStart(buildDir, configDir)
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


