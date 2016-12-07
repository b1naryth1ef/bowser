package main

import (
	"./bowser"
)

func main() {
	sshd := bowser.NewSSHDState()
	sshd.Run()
}
