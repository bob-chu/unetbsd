package main

import (
	"encoding/json"
	"fmt"
)

func printNodeExpanded(path []string, cmds []*Command) {
	fmt.Println()

	for _, c := range cmds {
		childPath := append(path, c.Name)
		val := getValue(childPath)

		switch v := val.(type) {
		case map[string]interface{}:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			fmt.Printf("%s: <object> keys=%v\n\n", c.Name, keys)

		case []interface{}:
			fmt.Printf("%s: <array> (%d items)\n\n", c.Name, len(v))

		default:
			fmt.Printf("%s: %v\n\n", c.Name, v)
		}
	}

	fmt.Println("Commands:")
	for _, c := range cmds {
		if c.Run != nil {
			fmt.Println(" -", c.Name)
		}
	}
	fmt.Println()
}

func printFullJSON() {
	data, _ := json.MarshalIndent(config, "", "  ")
	fmt.Println(string(data))
}
