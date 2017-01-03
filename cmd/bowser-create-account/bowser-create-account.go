package main

/*
	This script is responsible for provisioning and adding user accounts to our
	configuration. Generally it was meant to be run on the bastion box with the
	configuration path passed, thus automatically adding the account.
*/

import (
	"bufio"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/b1naryth1ef/bowser/lib"
	"github.com/mdp/qrterminal"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

var configPath = flag.String("config", "config.json", "path to config file")

func readPassword(attempts int) string {
	// Create a raw terminal so we can read the password without echo
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}

	// Restore terminal
	defer terminal.Restore(0, oldState)
	defer fmt.Printf("\r\n")

	// Give the user N attempts
	for i := 0; i < attempts; i++ {
		fmt.Printf("\rPassword: ")
		a, _ := terminal.ReadPassword(0)
		fmt.Printf("\n\rConfirm: ")
		b, _ := terminal.ReadPassword(0)

		if string(a) == string(b) {
			return string(a)
		}
	}

	return ""
}

func main() {
	flag.Parse()
	reader := bufio.NewReader(os.Stdin)

	// Grab username
	fmt.Printf("Username: ")
	username, _ := reader.ReadString('\n')

	// Grab SSH Public key
	fmt.Printf("SSH Public Key: ")
	sshKey, _ := reader.ReadString('\n')

	// Grab password
	password := readPassword(3)
	if password == "" {
		return
	}
	bcryptHash, _ := bcrypt.GenerateFromPassword([]byte(password), 12)

	// Generate TOTP code
	totpRaw := make([]byte, 32)
	_, err := rand.Read(totpRaw)
	if err != nil {
		fmt.Println("Failed to generate TOTP token")
		return
	}

	// Encode the TOTP token as base32 and truncate to 16 characters
	totpEncoded := base32.StdEncoding.EncodeToString(totpRaw)[:16]

	// Generate and display TOTP QR code
	qrterminal.Generate(fmt.Sprintf(
		"otpauth://totp/SSH:%s?secret=%s",
		username[:len(username)-1],
		totpEncoded,
	), qrterminal.H, os.Stdout)
	fmt.Printf("Please scan the above QR code with your TOTP app (or enter manually: `%s`)", totpEncoded)
	reader.ReadString('\n')

	// Create a new account struct
	account := bowser.Account{
		Username:   username[:len(username)-1],
		Password:   string(bcryptHash),
		SSHKeysRaw: []string{sshKey[:len(sshKey)-1]},
		MFA:        bowser.AccountMFA{TOTP: string(totpEncoded)},
	}

	// If the configuration path was passed, we can attempt to append this to the
	//  accounts file.
	if *configPath != "" {
		config, err := bowser.LoadConfig(*configPath)
		if err != nil {
			fmt.Printf("Failed to load config: %v\n", err)
			return
		}

		accounts, err := config.LoadAccounts()
		if err != nil {
			fmt.Printf("Failed to load accounts: %v\n", err)
			return
		}

		err = config.SaveAccounts(append(accounts, account))
		if err != nil {
			fmt.Printf("Failed to save accounts: %v\n", err)
			return
		}
	} else {
		// Otherwise, we just echo the payload to stdout
		data, _ := json.Marshal(account)
		fmt.Printf("\r\n%s\n", data)
	}
}
