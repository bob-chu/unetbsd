package main

import "fmt"

func executor(input string) {
	words := splitWords(input)
	if len(words) == 0 {
		return
	}
	runCommand(rootCommands, words, []string{})
}

func runCommand(cmds []*Command, words []string, path []string) {
	if len(words) == 0 {
		printNodeExpanded(path, cmds)
		return
	}

	for _, c := range cmds {
		if c.Name == words[0] {

			if c.Run != nil {
				c.Run(words[1:])
				return
			}

			runCommand(c.Sub, words[1:], append(path, c.Name))
			return
		}
	}

	fmt.Println("Unknown command:", words[0])
}
