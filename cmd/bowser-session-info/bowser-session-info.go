package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

func main() {
	// First grab ssh agent information, and setup an agent client
	authSock := os.Getenv("SSH_AUTH_SOCK")

	if authSock == "" {
		fmt.Printf("Invalid SSH_AUTH_SOCK, do you have an agent running / forwarded?\n")
		return
	}

	socket, err := net.Dial("unix", authSock)
	if err != nil {
		fmt.Printf("Error connecting to SSH_AUTH_SOCK: %v\n", err)
		return
	}

	client := agent.NewClient(socket)

	// Now that we have a client, grab the keys and sign some data
	keys, err := client.List()
	if err != nil {
		fmt.Printf("Failed to list keys: %v\n", err)
		return
	}

	timestamp := fmt.Sprintf("%v", int32(time.Now().Unix()))

	// TODO: need cli flag for selecting the correct key to use
	sig, err := client.Sign(keys[0], []byte(timestamp))
	if err != nil {
		fmt.Printf("Failed to sign an authentication key: %v\n", err)
		return
	}

	// Now that we have an auth signature, we need to make some requests
	parts := strings.Split(os.Getenv("SSH_CLIENT"), " ")
	if len(parts) < 2 {
		fmt.Printf("Invalid SSH_CLIENT information: %v\n", parts)
		return
	}

	// Build the request
	httpClient := &http.Client{}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("http://%s:13432/sessions/find/%s:%s", parts[0], parts[0], parts[1]),
		nil)

	if err != nil {
		fmt.Printf("Failed to create HTTP request: %s\n", err)
		return
	}

	// Set the various headers we need
	req.Header.Set("SSH-Auth-Key", keys[0].String())
	req.Header.Set("SSH-Auth-Connection", fmt.Sprintf("%s:%s", parts[0], parts[1]))
	req.Header.Set("SSH-Auth-Signature", base64.StdEncoding.EncodeToString(sig.Blob))
	req.Header.Set("SSH-Auth-Timestamp", timestamp)

	// Make the request
	res, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("Failed to make HTTP request: %s\n", err)
		return
	}

	// Check the status
	if res.StatusCode != 200 {
		fmt.Printf("Error: %v\n", res.StatusCode)
		return
	}

	data, err := ioutil.ReadAll(res.Body)
	fmt.Printf("%v\n", string(data))
}
