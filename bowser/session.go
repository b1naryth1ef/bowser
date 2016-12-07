package bowser

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	_ "github.com/pquerna/otp/totp"
	"github.com/satori/go.uuid"
	"github.com/uber-go/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	_ "golang.org/x/crypto/ssh/terminal"
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
	UUID    string
	State   *SSHDState
	Account *Account
	Conn    *ssh.ServerConn
	log     zap.Logger
}

func NewSSHSession(state *SSHDState, conn *ssh.ServerConn) *SSHSession {
	id := uuid.NewV4()

	strID, _ := id.MarshalText()

	return &SSHSession{
		UUID:    string(strID),
		State:   state,
		Account: state.accounts[conn.User()],
		Conn:    conn,
		log:     state.log,
	}
}

func (s *SSHSession) handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go s.handleChannel(newChannel)
	}
}

func (s *SSHSession) handleChannel(newChannel ssh.NewChannel) {
	switch newChannel.ChannelType() {
	case "direct-tcpip":
		s.handleChannelForward(newChannel)
	default:
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type"))
		return
	}
}

type channelOpenDirectMsg struct {
	RAddr string
	RPort uint32
	LAddr string
	LPort uint32
}

func (s *SSHSession) handleChannelForward(newChannel ssh.NewChannel) {
	// Attempt to open a channel to the auth agent
	agentChan, agentReqs, err := s.Conn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		newChannel.Reject(ssh.Prohibited, "you must have an ssh agent open and forwarded")
		return
	}

	// Just discard further requests
	go ssh.DiscardRequests(agentReqs)

	// Open an agent on the channel
	ag := agent.NewClient(agentChan)

	cert, privateKey, err := s.State.ca.Generate("test", "andrei")
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
		log.Printf("Failed to add key: %v", err)
	}

	var msg channelOpenDirectMsg
	ssh.Unmarshal(newChannel.ExtraData(), &msg)
	address := fmt.Sprintf("%s:%d", msg.RAddr, msg.RPort)

	// TODO: address validation

	for _, wp := range s.State.WebhookProviders {
		wp.NotifyNewSession(s.Conn.User(), address)
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
