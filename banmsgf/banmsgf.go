package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	found_msgf := false
	for _, file := range os.Args[1:] {
		if !strings.HasSuffix(file, ".go") {
			continue
		}

		f, err := os.Open(file)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for i := 1; scanner.Scan(); i++ {
			if strings.Contains(scanner.Text(), ".Msgf(") {
				text := scanner.Text()
				fmt.Printf("%s:%d: %s\n", file, i, text[:len(text)-1])
				found_msgf = true
			}
		}
	}

	if found_msgf {
		os.Exit(1)
	}
}
