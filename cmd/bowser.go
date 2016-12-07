package main

import (
	"github.com/b1naryth1ef/bowser/lib"
)

func main() {
	sshd := bowser.NewSSHDState()
	sshd.Run()
}
