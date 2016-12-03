package bowser

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/kr/pty"
	"github.com/pquerna/otp/totp"
	"github.com/satori/go.uuid"
	"github.com/uber-go/zap"
	"golang.org/x/crypto/ssh"
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
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	connection, requests, err := newChannel.Accept()
	if err != nil {
		s.log.Warn("Could not accept channel", zap.Error(err))
		return
	}

	s.log.Info(
		"Connection Opened",
		zap.Object("uuid", s.UUID),
		zap.Object("account", s.Account),
		zap.Object("connection", s.Conn.RemoteAddr()),
	)

	term := terminal.NewTerminal(connection, "")
	term.Write([]byte(fmt.Sprintf("Session %v opened\r\n", s.UUID)))
	term.Write([]byte(s.State.Config.MOTD + "\r\n"))

	// Query and validate MFA
	valid := false

	for i := 0; i < 3; i++ {
		term.Write([]byte("MFA Code: "))
		line, err := term.ReadLine()

		if err != nil {
			break
		}

		if totp.Validate(line, s.Account.MFA.TOTP) {
			valid = true
			break
		}

		s.log.Warn(
			"Invalid MFA entered",
			zap.Object("uuid", s.UUID),
			zap.Object("username", s.Account.Username),
			zap.Object("connection", s.Conn.RemoteAddr()),
			zap.String("code", line))
	}

	loginAttemptID := s.State.db.insertLoginAttempt(s)

	// Close connection if its not valid
	if !valid {
		s.log.Warn(
			"Connection closed for invalid MFA",
			zap.Object("uuid", s.UUID),
			zap.Object("username", s.Account.Username),
			zap.Object("connection", s.Conn.RemoteAddr()))
		connection.Close()
		return
	}

	s.State.db.insertSession(s.UUID, loginAttemptID)

	// Start shell session
	bash := exec.Command(s.Account.Shell)

	// Prepare teardown function
	close := func() {
		s.log.Info(
			"Connection closed normally",
			zap.Object("uuid", s.UUID),
			zap.Object("username", s.Account.Username),
			zap.Object("connection", s.Conn.RemoteAddr()))

		s.State.db.endSession(s.UUID)
		connection.Close()

		_, err := bash.Process.Wait()
		if err != nil {
			s.log.Warn(
				"Failed to exit shell",
				zap.Object("uuid", s.UUID),
				zap.Object("username", s.Account.Username),
				zap.Object("connection", s.Conn.RemoteAddr()),
				zap.String("shell", s.Account.Shell),
				zap.Error(err))
		}
	}

	// Allocate a terminal for this channel
	s.log.Info(
		"Shell Created",
		zap.Object("uuid", s.UUID),
		zap.Object("username", s.Account.Username),
		zap.Object("connection", s.Conn.RemoteAddr()),
		zap.String("shell", s.Account.Shell))

	bashf, err := pty.Start(bash)
	if err != nil {
		s.log.Warn("could not start pty", zap.String("uuid", s.UUID), zap.Error(err))
		close()
		return
	}

	// Handle sending PTY data to the session while also logging to file
	var once sync.Once
	go func() {
		var err error
		var size int
		buffer := make([]byte, 1024)

		for err != io.EOF {
			size, err = connection.Read(buffer)
			bashf.Write(buffer[:size])
		}

		once.Do(close)
	}()

	go func() {
		var err error
		var size int
		buffer := make([]byte, 1024)

		for err != io.EOF {
			size, err = bashf.Read(buffer)
			connection.Write(buffer[:size])

			if s.RecordingFile != nil {
				s.RecordingFile.Write(buffer[:size])
			}
		}

		once.Do(close)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
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
