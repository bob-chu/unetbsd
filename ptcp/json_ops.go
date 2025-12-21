package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

func getValue(path []string) interface{} {
	var cur interface{} = config
	for _, p := range path {
		switch node := cur.(type) {
		case map[string]interface{}:
			cur = node[p]
		case []interface{}:
			idx, _ := strconv.Atoi(p)
			cur = node[idx]
		default:
			return nil
		}
	}
	return cur
}

func setValue(path []string, newVal interface{}) {
	if len(path) == 1 {
		config[path[0]] = newVal
		maybeAutoSave()
		return
	}

	parent := getValue(path[:len(path)-1])
	last := path[len(path)-1]

	switch node := parent.(type) {
	case map[string]interface{}:
		node[last] = newVal
	case []interface{}:
		idx, _ := strconv.Atoi(last)
		node[idx] = newVal
	}

	maybeAutoSave()
}

func deleteValue(path []string) {
	if len(path) == 1 {
		delete(config, path[0])
		rebuildCommands()
		maybeAutoSave()
		return
	}

	parent := getValue(path[:len(path)-1])
	last := path[len(path)-1]

	switch node := parent.(type) {
	case map[string]interface{}:
		delete(node, last)
	case []interface{}:
		idx, _ := strconv.Atoi(last)
		node = append(node[:idx], node[idx+1:]...)
		setValue(path[:len(path)-1], node)
	}

	rebuildCommands()
	maybeAutoSave()
}

func addObjectValue(path []string, key string, val interface{}) {
	obj := getValue(path).(map[string]interface{})
	obj[key] = val
	rebuildCommands()
	maybeAutoSave()
}

func addArrayValue(path []string, val interface{}) {
	arr := getValue(path).([]interface{})
	arr = append(arr, val)
	setValue(path, arr)
	rebuildCommands()
}

func parseValue(s string) interface{} {
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	if s == "true" || s == "false" {
		return s == "true"
	}
	return s
}

func parseJSONOrPrimitive(s string) interface{} {
	var js interface{}
	if json.Unmarshal([]byte(s), &js) == nil {
		return js
	}
	return parseValue(s)
}

func saveConfig() {
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configPath, data, 0644)
	fmt.Println("Config saved to", configPath)
}

func maybeAutoSave() {
	if autosave {
		saveConfig()
	}
}
