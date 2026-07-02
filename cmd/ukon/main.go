// Command ukon is the single entry point for Univerkon Control.
//
// Three faces of the same binary (spec §1):
//
//	ukon --ui               starts the web UI + API server
//	ukon --tui               starts the terminal UI (Bubble Tea)
//	ukon server add ...       runs a CLI subcommand directly, no server needed
//
// This file is a scaffold: flag parsing and mode dispatch are real, the
// modes themselves are not implemented yet. See internal/ for the domain
// packages each mode will wire together.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	ui := flag.Bool("ui", false, "start the web UI and API server")
	tui := flag.Bool("tui", false, "start the terminal UI")
	port := flag.Int("port", 8080, "port for the web UI/API server")
	flag.Parse()

	switch {
	case *ui:
		runUI(*port)
	case *tui:
		runTUI()
	default:
		runCLI(flag.Args())
	}
}

func runUI(port int) {
	fmt.Fprintf(os.Stderr, "ukon: --ui not implemented yet (would listen on :%d)\n", port)
	os.Exit(1)
}

func runTUI() {
	fmt.Fprintln(os.Stderr, "ukon: --tui not implemented yet")
	os.Exit(1)
}

func runCLI(args []string) {
	if len(args) == 0 {
		fmt.Println("ukon: no subcommand given. Try --ui, --tui, or `ukon server add`. See --help.")
		return
	}
	fmt.Fprintf(os.Stderr, "ukon: subcommand %q not implemented yet\n", args[0])
	os.Exit(1)
}
