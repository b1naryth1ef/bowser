package bowser

/*
	This file contains a client API implementation that mostly focuses on authentication.
*/

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

var (
	InvalidSSHAuthSock          = errors.New("Invalid SSH_AUTH_SOCK, is an agent running")
	InvalidSSHClientInformation = errors.New("Invalid SSH_CLIENT information")
	APIRequestFailed            = errors.New("API Request failed")
)

// Returns the remote IP/Port for the current SSH Connection
func GetSSHClientConnection() (string, string, error) {
	parts := strings.Split(os.Getenv("SSH_CLIENT"), " ")
	if len(parts) < 2 {
		return "", "", InvalidSSHClientInformation
	}

	return parts[0], parts[1], nil
}

// Attempts to authenticate an HTTP Request with the current SSH connection/agent
//  information.
func AuthenticateRequest(req *http.Request) error {
	// First grab ssh agent information, and setup an agent client
	authSock := os.Getenv("SSH_AUTH_SOCK")

	if authSock == "" {
		return InvalidSSHAuthSock
	}

	socket, err := net.DialTimeout("unix", authSock, 1*time.Second)
	if err != nil {
		return err
	}

	client := agent.NewClient(socket)

	// Now that we have a client, grab the keys and sign some data
	keys, err := client.List()
	if err != nil {
		return err
	}

	timestamp := fmt.Sprintf("%v", int32(time.Now().Unix()))

	sig, err := client.Sign(keys[0], []byte(timestamp))
	if err != nil {
		return err
	}

	sourceHost, sourcePort, err := GetSSHClientConnection()
	if err != nil {
		return err
	}

	// Set the various headers we need
	req.Header.Set("SSH-Auth-Key", keys[0].String())
	req.Header.Set("SSH-Auth-Connection", fmt.Sprintf("%s:%s", sourceHost, sourcePort))
	req.Header.Set("SSH-Auth-Signature", base64.StdEncoding.EncodeToString(sig.Blob))
	req.Header.Set("SSH-Auth-Timestamp", timestamp)

	return nil
}

type BowserAPIClient struct {
	client *http.Client
	url    string
}

func NewBowserAPIClient(proto string, port string) (*BowserAPIClient, error) {
	host, _, err := GetSSHClientConnection()
	if err != nil {
		return nil, err
	}

	return &BowserAPIClient{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		url: fmt.Sprintf("%s://%s:%s", proto, host, port),
	}, nil
}

func (b *BowserAPIClient) GetCurrentSessionInfo() (*JSONSession, error) {
	remoteHost, remotePort, err := GetSSHClientConnection()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/sessions/find/%s:%s", b.url, remoteHost, remotePort),
		nil)

	if err != nil {
		return nil, err
	}

	// Authenticate the request
	err = AuthenticateRequest(req)
	if err != nil {
		return nil, err
	}

	res, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}

	// Check the status
	if res.StatusCode != 200 {
		return nil, APIRequestFailed
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	result := &JSONSession{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
