package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
)

const (
	COLOR_BOLD  = "\033[1m"
	COLOR_RED   = "\033[31m"
	COLOR_RESET = "\033[0m"
)

var stringerRe = regexp.MustCompile(`\.Str\(([^)]*?)\.String\(\)\)`)

func main() {
	var replacedStringer bool
	for _, file := range os.Args[1:] {
		contents, err := os.ReadFile(file)
		if err != nil {
			panic(err)
		}

		var modifiedFile bool
		lines := bytes.Split(contents, []byte("\n"))
		for i, line := range lines {
			for _, match := range stringerRe.FindAllSubmatchIndex(line, -1) {
				replacedStringer = true

				if !modifiedFile {
					fmt.Printf("\n%s%s%s\n", COLOR_BOLD, file, COLOR_RESET)
					modifiedFile = true
				}
				fmt.Printf("%d: %s.%s%sStr%s(%s.%s%sString()%s)\n",
					i+1,
					line[:match[0]],
					COLOR_BOLD, COLOR_RED, COLOR_RESET,
					line[match[2]:match[3]],
					COLOR_BOLD, COLOR_RED, COLOR_RESET,
				)
			}
		}

		newLines := make([][]byte, len(lines))
		for i, line := range lines {
			newLines[i] = stringerRe.ReplaceAll(line, []byte(`.Stringer($1)`))
		}
		err = os.WriteFile(file, bytes.Join(newLines, []byte("\n")), 0644)
		if err != nil {
			panic(err)
		}
	}

	if replacedStringer {
		os.Exit(1)
	}
}
