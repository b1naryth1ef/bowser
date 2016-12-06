package bowser

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/pquerna/otp/totp"
	"github.com/satori/go.uuid"
	"github.com/uber-go/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

type AccountKey struct {
	Account *Account
	Key     ssh.PublicKey
	Comment string
	Options []string
}

func NewAccountKey(account *Account, rawKey []byte) (*AccountKey, error) {
	key, comment, options, _, err := ssh.ParseAuthorizedKey(rawKey)
	if err != nil {
		return nil, err
	}

	return &AccountKey{
		Account: account,
		Key:     key,
		Comment: comment,
		Options: options,
	}, nil
}

func (key *AccountKey) ID() string {
	return string(key.Key.Marshal())
}

type SSHSession struct {
	UUID          string
	State         *SSHDState
	Account       *Account
	Conn          *ssh.ServerConn
	RecordingFile *os.File
	Verified      bool
	log           zap.Logger
}

func NewSSHSession(state *SSHDState, conn *ssh.ServerConn) *SSHSession {
	id := uuid.NewV4()

	strID, _ := id.MarshalText()
	path := state.Config.RecordingPath + string(strID) + ".rec"
	file, err := os.Create(path)

	// This is ok, we null check below
	if err != nil {
		state.log.Warn("Couldn't create recording file", zap.Error(err), zap.String("path", path))
	}

	return &SSHSession{
		UUID:          string(strID),
		State:         state,
		Account:       state.accounts[conn.User()],
		Conn:          conn,
		RecordingFile: file,
		Verified:      false,
		log:           state.log,
	}
}

func (s *SSHSession) handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go s.handleChannel(newChannel)
	}
}

func (s *SSHSession) handleChannel(newChannel ssh.NewChannel) {
	log.Printf("session opened w/ %v", newChannel.ChannelType())
	switch newChannel.ChannelType() {
	case "session":
		s.handleChannelSession(newChannel)
	case "direct-tcpip":
		s.handleChannelForward(newChannel)
	default:
		log.Printf("Unhandled channel type: %v", newChannel.ChannelType())
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type"))
		return
	}
}

func (s *SSHSession) handleChannelSession(newChannel ssh.NewChannel) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		s.log.Warn("Could not accept channel", zap.Error(err))
		return
	}
	go ssh.DiscardRequests(requests)

	s.log.Info(
		"Connection Opened",
		zap.Object("uuid", s.UUID),
		zap.Object("account", s.Account),
		zap.Object("connection", s.Conn.RemoteAddr()),
	)

	term := terminal.NewTerminal(connection, "")
	term.Write([]byte(fmt.Sprintf("Session %v opened\r\n", s.UUID)))

	// Check what we need to do if TOTP is disabled
	if s.Account.MFA.TOTP == "" {
		if s.State.Config.ForceMFA {
			s.log.Warn(
				"User does not have MFA enabled, but its forced",
				zap.Object("uuid", s.UUID),
				zap.Object("username", s.Account.Username),
				zap.Object("connection", s.Conn.RemoteAddr()))
			connection.Close()
			return
		} else {
			s.log.Warn("User logged in with disabled MFA",
				zap.Object("uuid", s.UUID),
				zap.Object("username", s.Account.Username),
				zap.Object("connection", s.Conn.RemoteAddr()))
			s.Verified = true
		}
	}

	// If they are not verified yet, we need to check MFA
	if !s.Verified {
		for i := 0; i < 3; i++ {
			term.Write([]byte("MFA Code: "))
			line, err := term.ReadLine()

			if err != nil {
				break
			}

			if totp.Validate(line, s.Account.MFA.TOTP) {
				s.Verified = true
				break
			}

			s.log.Warn(
				"Invalid MFA entered",
				zap.Object("uuid", s.UUID),
				zap.Object("username", s.Account.Username),
				zap.Object("connection", s.Conn.RemoteAddr()),
				zap.String("code", line))
		}

		// Close connection if its not valid
		if !s.Verified {
			s.log.Warn(
				"Connection closed for invalid MFA",
				zap.Object("uuid", s.UUID),
				zap.Object("username", s.Account.Username),
				zap.Object("connection", s.Conn.RemoteAddr()))
			connection.Close()
			return
		}
	}

	// TODO: better way to sit on connection?
	if s.Account.Shell == "" {
		return
	}
}

// =======================

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

type channelOpenDirectMsg struct {
	RAddr string
	RPort uint32
	LAddr string
	LPort uint32
}

func (s *SSHSession) handleChannelForward(newChannel ssh.NewChannel) {
	// Close the session right away if they aren't authed yet
	if !s.Verified {
		newChannel.Reject(ssh.Prohibited, "you must authenticate in another channel")
		return
	}

	// Attempt to open a channel to the auth agent
	agentChan, agentReqs, err := s.Conn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		newChannel.Reject(ssh.Prohibited, "you must have an ssh agent open and forwarded")
		return
	}

	go ssh.DiscardRequests(agentReqs)

	// Open an agent on the channel
	ag := agent.NewClient(agentChan)

	cert, privateKey, err := s.State.ca.Generate("andrei")
	if err != nil {
		log.Printf("Failed to generate SSH cert/key: %v", err)
		return
	}

	err = ag.Add(agent.AddedKey{
		PrivateKey:   privateKey,
		Certificate:  cert,
		LifetimeSecs: 60,
		Comment:      "temporary ssh certificate",
	})

	if err != nil {
		log.Printf("Failed toadd key: %v", err)
	}

	keys, _ := ag.List()
	log.Printf("keys: %v", keys)

	var msg channelOpenDirectMsg
	ssh.Unmarshal(newChannel.ExtraData(), &msg)
	address := fmt.Sprintf("%s:%d", msg.RAddr, msg.RPort)

	// TODO: address validation

	for _, wp := range s.State.WebhookProviders {
		log.Printf("err: %v", wp.NotifyNewSession(s.Conn.User(), address))
	}

	conn, err := net.Dial("tcp", address)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("error: %v", err))
		return
	}

	channel, reqs, err := newChannel.Accept()

	go ssh.DiscardRequests(reqs)
	var closer sync.Once
	closeFunc := func() {
		agentChan.Close()
		channel.Close()
		conn.Close()
	}

	go func() {
		io.Copy(channel, conn)
		closer.Do(closeFunc)
	}()

	go func() {
		io.Copy(conn, channel)
		closer.Do(closeFunc)
	}()
}
