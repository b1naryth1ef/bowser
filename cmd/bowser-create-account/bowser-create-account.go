package main

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

func main() {
	flag.Parse()
	reader := bufio.NewReader(os.Stdin)

	// Grab username
	fmt.Printf("Username: ")
	username, _ := reader.ReadString('\n')

	// Grab SSH key
	fmt.Printf("SSH Key: ")
	sshKey, _ := reader.ReadString('\n')

	// Grab password
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(0, oldState)

	fmt.Printf("\rPassword: ")
	a, _ := terminal.ReadPassword(0)
	fmt.Printf("\n\rConfirm: ")
	b, _ := terminal.ReadPassword(0)

	if string(a) != string(b) {
		fmt.Println("\rPasswords do not match!")
		return
	}

	bcryptHash, _ := bcrypt.GenerateFromPassword(a, 12)

	// Restore terminal
	terminal.Restore(0, oldState)
	fmt.Printf("\r\n")

	// Generate TOTP code
	totpRaw := make([]byte, 32)
	_, err = rand.Read(totpRaw)
	if err != nil {
		fmt.Println("Failed to generate TOTP token")
		return
	}
	totpEncoded := base32.StdEncoding.EncodeToString(totpRaw)[:16]

	// Generate and display TOTP QR code
	qrterminal.Generate(fmt.Sprintf(
		"otpauth://totp/SSH:%s?secret=%s",
		username[:len(username)-1],
		totpEncoded,
	), qrterminal.H, os.Stdout)
	fmt.Printf("Please scan the above QR code with your TOTP app (or enter manually: `%s`)", totpEncoded)
	reader.ReadString('\n')

	// Create and serialize account to stdout
	account := bowser.Account{
		Username:   username[:len(username)-1],
		Password:   string(bcryptHash),
		SSHKeysRaw: []string{sshKey[:len(sshKey)-1]},
		MFA:        bowser.AccountMFA{TOTP: string(totpEncoded)},
	}

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
		data, _ := json.Marshal(account)
		fmt.Printf("\r\n%s\n", data)
	}
}
