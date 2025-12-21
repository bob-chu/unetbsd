package main

import "fmt"

func rebuildCommands() {
	rootCommands = nil
	for key, val := range config {
		rootCommands = append(rootCommands, buildCommandsFromJSON(key, val, []string{key}))
	}
	rootCommands = append(rootCommands, staticCommands...)
}

func buildCommandsFromJSON(name string, node interface{}, path []string) *Command {
	cmd := &Command{
		Name:        name,
		Description: fmt.Sprintf("Node: %s", name),
	}

	switch v := node.(type) {

	case map[string]interface{}:
		for key, val := range v {
			cmd.Sub = append(cmd.Sub, buildCommandsFromJSON(key, val, append(path, key)))
		}

		cmd.Sub = append(cmd.Sub,
			&Command{
				Name:        "add",
				Description: "Add a new key to this object",
				Run: func(args []string) {
					if len(args) < 2 {
						fmt.Println("Usage: <path> add <key> <value>")
						return
					}
					addObjectValue(path, args[0], parseJSONOrPrimitive(args[1]))
					fmt.Println("Added key:", args[0])
				},
			},
			&Command{
				Name:        "delete",
				Description: "Delete a key in this object",
				Run: func(args []string) {
					if len(args) < 1 {
						fmt.Println("Usage: <path> delete <key>")
						return
					}
					deleteValue(append(path, args[0]))
				},
			},
		)

	case []interface{}:
		for i, val := range v {
			index := fmt.Sprintf("%d", i)
			cmd.Sub = append(cmd.Sub, buildCommandsFromJSON(index, val, append(path, index)))
		}

		cmd.Sub = append(cmd.Sub,
			&Command{
				Name:        "add",
				Description: "Append a new element to this array",
				Run: func(args []string) {
					if len(args) < 1 {
						fmt.Println("Usage: <path> add <value>")
						return
					}
					addArrayValue(path, parseJSONOrPrimitive(args[0]))
					fmt.Println("Appended new element")
				},
			},
			&Command{
				Name:        "delete",
				Description: "Delete an array element",
				Run: func(args []string) {
					if len(args) < 1 {
						fmt.Println("Usage: <path> delete <index>")
						return
					}
					deleteValue(append(path, args[0]))
				},
			},
		)

	default:
		cmd.Sub = []*Command{
			{
				Name:        "show",
				Description: "Show value",
				Run: func(args []string) {
					fmt.Println(getValue(path))
				},
			},
			{
				Name:        "edit",
				Description: "Edit value",
				Run: func(args []string) {
					if len(args) < 1 {
						fmt.Println("Usage: <path> edit <new_value>")
						return
					}
					setValue(path, parseJSONOrPrimitive(args[0]))
					fmt.Println("Value updated")
				},
			},
			{
				Name:        "delete",
				Description: "Delete this value",
				Run: func(args []string) {
					deleteValue(path)
					fmt.Println("Deleted")
				},
			},
		}
	}

	return cmd
}
