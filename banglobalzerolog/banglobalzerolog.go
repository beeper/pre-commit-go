package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
)

func main() {
	var found bool
	ignoreCommentRegex := regexp.MustCompile(`//\s+zerolog-allow-global-log`)

	for _, filename := range os.Args[1:] {
		file, err := os.Open(filename)
		if err != nil {
			panic(fmt.Errorf("Unable to open %s: %w", filename, err))
		}

		fileBytes, err := io.ReadAll(file)
		if err != nil {
			panic(fmt.Errorf("Unable to read %s: %w", filename, err))
		}
		for i, line := range bytes.Split(fileBytes, []byte("\n")) {
			if bytes.Contains(line, []byte(`"github.com/rs/zerolog/log"`)) && !ignoreCommentRegex.Match(line) {
				fmt.Printf("line %+s\n", line)
				fmt.Printf("Found global zerolog in %s:%d\n", filename, i+1)
				found = true
			}
		}
	}

	if found {
		os.Exit(1)
	}
}
