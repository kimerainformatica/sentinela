//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "o agente Sentinela suporta apenas Windows nesta versão")
	os.Exit(1)
}
