package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(0, oldState)

	fmt.Printf("\rPassword: ")
	a, _ := terminal.ReadPassword(0)
	fmt.Printf("\rConfirm: ")
	b, _ := terminal.ReadPassword(0)

	if string(a) != string(b) {
		fmt.Println("\rPasswords do not match!")
		return
	}

	fmt.Printf("\rOne moment, crunching numbers...")
	res, _ := bcrypt.GenerateFromPassword(a, 15)
	terminal.Restore(0, oldState)
	fmt.Printf("\r\n%s\n", res)
}
