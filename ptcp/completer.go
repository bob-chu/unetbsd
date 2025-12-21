package main

import (
	"os"
	"strconv"
	"strings"

	prompt "github.com/c-bata/go-prompt"
)

func completer(d prompt.Document) []prompt.Suggest {
	words := splitWords(d.TextBeforeCursor())
	return completeLevel(rootCommands, words)
}

func completeLevel(cmds []*Command, words []string) []prompt.Suggest {
	if len(words) == 0 {
		return toSuggest(cmds)
	}

	// ------------------------------------------------------------
	// Special handling for "generate"
	// ------------------------------------------------------------
	if words[0] == "generate" {
		return generateCompleter(words)
	}

	// ------------------------------------------------------------
	// Special handling for "run"
	// ------------------------------------------------------------
	if words[0] == "run" {
		return runCompleter(words)
	}

	// ------------------------------------------------------------
	// Normal command tree traversal
	// ------------------------------------------------------------
	for _, c := range cmds {
		if c.Name == words[0] {
			return completeLevel(c.Sub, words[1:])
		}
	}

	return prompt.FilterHasPrefix(toSuggest(cmds), words[0], true)
}

func toSuggest(cmds []*Command) []prompt.Suggest {
	out := []prompt.Suggest{}
	for _, c := range cmds {
		out = append(out, prompt.Suggest{
			Text:        c.Name,
			Description: c.Description,
		})
	}
	return out
}

func splitWords(s string) []string {
	return strings.Fields(s)
}

//
// ============================================================
//  AUTO-COMPLETION FOR "generate"
// ============================================================
//

func generateCompleter(words []string) []prompt.Suggest {
	// Case: user typed only "generate"
	if len(words) == 1 {
		return []prompt.Suggest{
			{Text: "http_client", Description: "Generate client configs"},
			{Text: "http_server", Description: "Generate server configs"},
			{Text: "both", Description: "Generate both client + server"},
			{Text: "list", Description: "List available templates"},
		}
	}

	// Case: "generate list"
	if words[1] == "list" {
		return []prompt.Suggest{}
	}

	// Case: "generate <template>"
	if len(words) == 2 {
		return countSuggestions()
	}

	// Case: "generate <template> <count>"
	if len(words) == 3 {
		return directorySuggestions()
	}
	// Case: "generate <template> <count> <numa_node>"
	if len(words) == 4 {
		return []prompt.Suggest{
			{Text: "0", Description: "NUMA node 0"},
			{Text: "1", Description: "NUMA node 1"},
		}
	}

	return []prompt.Suggest{}
}

//
// ============================================================
//  AUTO-COMPLETION FOR "run"
// ============================================================
//

func runCompleter(words []string) []prompt.Suggest {
	// Case: user typed only "run"
	if len(words) == 1 {
		return []prompt.Suggest{
			{Text: "start", Description: "Start a test"},
			{Text: "stop", Description: "Stop a test"},
		}
	}

	// Case: "run start"
	if words[1] == "start" {
		if len(words) == 2 {
			return directorySuggestions()
		}
		if len(words) == 3 {
			return directorySuggestions()
		}
	}

	return []prompt.Suggest{}
}

//
// ============================================================
//  COUNT SUGGESTIONS (1–128)
// ============================================================
//

func countSuggestions() []prompt.Suggest {
	out := []prompt.Suggest{}
	for i := 1; i <= 128; i++ {
		s := strconv.Itoa(i)
		out = append(out, prompt.Suggest{
			Text:        s,
			Description: "Count",
		})
	}
	return out
}

//
// ============================================================
//  DIRECTORY SUGGESTIONS
// ============================================================
//

func directorySuggestions() []prompt.Suggest {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil
	}

	out := []prompt.Suggest{}
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, prompt.Suggest{
				Text:        e.Name(),
				Description: "Directory",
			})
		}
	}

	// Always allow new directory
	out = append(out, prompt.Suggest{
		Text:        "<new_dir>",
		Description: "Create a new output directory",
	})

	return out
}
