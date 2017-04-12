package main

import (
	"fmt"

	"github.com/b1naryth1ef/bowser/lib"
)

func main() {
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
