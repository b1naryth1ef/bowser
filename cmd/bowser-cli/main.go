package main

import (
	"fmt"
	"os"

	"flag"
	"github.com/b1naryth1ef/bowser/lib"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("bowser-cli: info | ls | jump\n")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "info":
		handleInfoCommand()
	case "ls":
		handleListCommand()
	case "jump":
		handleJumpCommand()
	default:
		fmt.Printf("unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func handleInfoCommand() {
	client, err := bowser.NewBowserAPIClient("http", "13432")
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}

	data, err := client.GetCurrentSessionInfo()
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}

	fmt.Printf("ID: %s\n", data.UUID)
	fmt.Printf("Username: %s\n", data.Username)
	fmt.Printf("Metadata: %s\n", data.Metadata)
}

func handleListCommand() {
	client, err := bowser.NewBowserAPIClient("http", "13432")
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}

	sessions, err := client.ListSessions()
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}

	for _, session := range *sessions {
		fmt.Printf("ID: %s\n", session.UUID)
		fmt.Printf("Username: %s\n", session.Username)
		fmt.Printf("Metadata: %s\n\n", session.Metadata)
	}
}

func handleJumpCommand() {
	command := flag.NewFlagSet("jump", flag.ExitOnError)
	destination := command.String("destination", "", "Destination for SSH jump")
	command.Parse(os.Args[2:])

	client, err := bowser.NewBowserAPIClient("http", "13432")
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}

	err = client.Jump(*destination)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	}
}
