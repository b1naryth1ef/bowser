package bowser

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"sync"

	"github.com/satori/go.uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// An account key represents a mapping of ssh public key to account
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

// An SSHSession represents one TCP connection, with one or more direct-tcpip channels
type SSHSession struct {
	UUID    string
	State   *SSHDState
	Account *Account
	Conn    *ssh.ServerConn

	verified bool
	log      *zap.Logger
}

func NewSSHSession(state *SSHDState, conn *ssh.ServerConn) *SSHSession {
	id := uuid.NewV4()

	strID, _ := id.MarshalText()

	state.log.Info(
		"New SSH session created",
		zap.String("id", string(strID)),
		zap.String("username", conn.User()),
		zap.String("session-id", string(conn.SessionID())),
		zap.String("client-version", string(conn.ClientVersion())),
		zap.String("remote-addr", conn.RemoteAddr().String()))

	return &SSHSession{
		UUID:    string(strID),
		State:   state,
		Account: state.accounts[conn.User()],
		Conn:    conn,
		log:     state.log,
	}
}

func (s *SSHSession) handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		go s.handleChannel(newChannel)
	}

	delete(s.State.sessions, s.UUID)
}

func (s *SSHSession) Close() {
	s.Conn.Close()
}

func (s *SSHSession) handleChannel(newChannel ssh.NewChannel) {
	switch newChannel.ChannelType() {
	case "direct-tcpip":
		s.handleChannelForward(newChannel)
	case "session":
		s.handleChannelSession(newChannel)
	default:
		s.log.Error(
			"Rejecting channel with invalid channel type",
			zap.String("type", newChannel.ChannelType()),
			zap.String("id", s.UUID))
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

type channelExecMsg struct {
	Command string
}

func (s *SSHSession) authenticateChannel(newChannel ssh.NewChannel) (*agent.Agent, *ssh.Channel, bool) {
	// Attempt to open a channel to the auth agent
	agentChan, agentReqs, err := s.Conn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		s.log.Error(
			"Rejecting forward: failed to open ssh agent",
			zap.String("id", s.UUID),
			zap.Error(err))
		newChannel.Reject(ssh.Prohibited, "you must have an ssh agent open and forwarded")
		return nil, nil, false
	}

	// Just discard further requests
	go ssh.DiscardRequests(agentReqs)

	// Open an agent on the channel
	ag := agent.NewClient(agentChan)

	// If the session has not been verified yet, we must do that now by taking a
	//  random string, requesting their agent encrypt it with a known public key,
	//  and validating the results. This verifies ownership of the public key, even
	//  though it is not used as the primary authentication scheme for the session.
	if !s.verified {
		signers, err := ag.Signers()
		if err != nil {
			s.log.Error(
				"Rejecting forward: failed to get list of signers from agent",
				zap.String("id", s.UUID),
				zap.Error(err))
			newChannel.Reject(ssh.Prohibited, "agent will not give us a list of signers")
			return nil, nil, false
		}

		// Iterate over all signers to find one with a valid publick ey
		for _, signer := range signers {
			// Check if the public key exists
			accountKey, exists := s.State.keys[string(signer.PublicKey().Marshal())]
			if !exists {
				continue
			}

			// Verify whether the public key is for the current sessions account
			if accountKey.Account != s.Account {
				continue
			}

			// If it is, validate a random string
			randomToken := make([]byte, 128)
			_, err := rand.Read(randomToken)
			if err != nil {
				s.log.Error(
					"Rejecting forward: failed to generate random token",
					zap.String("id", s.UUID),
					zap.Error(err))
				newChannel.Reject(ssh.Prohibited, "cannot generate random token")
				return nil, nil, false
			}

			// Sign the random token with the signer
			sig, err := signer.Sign(rand.Reader, randomToken)
			if err != nil {
				s.log.Error(
					"Rejecting forward: failed to sign random token",
					zap.String("id", s.UUID),
					zap.Error(err))
				newChannel.Reject(ssh.Prohibited, "cannot sign random token")
				return nil, nil, false
			}

			// Verify the signature
			err = accountKey.Key.Verify(randomToken, sig)
			if err != nil {
				s.log.Error(
					"Rejecting forward: failed to verify random token signature",
					zap.String("id", s.UUID),
					zap.Error(err))
				newChannel.Reject(ssh.Prohibited, "signature verification failed")
				return nil, nil, false
			}

			s.log.Info("Public key verification completed", zap.String("id", s.UUID))
			s.verified = true
			break
		}
	}

	return &ag, &agentChan, true
}

func (s *SSHSession) handleChannelForward(newChannel ssh.NewChannel) {
	// First we must validate the channel
	ag, agentChan, success := s.authenticateChannel(newChannel)
	if !success {
		return
	}

	// Now that we're verified, we must ask the SSH-CA to generate and sign a valid
	//  SSH key/cert that we can use to login.
	var username string
	if s.State.Config.ForceUser != "" {
		username = s.State.Config.ForceUser
	} else {
		username = s.Account.Username
	}

	var principals []string
	if len(s.Account.Principals) > 0 {
		principals = s.Account.Principals
	} else {
		principals = append(principals, username)
	}

	keyID := fmt.Sprintf("user[%s] / session[%s]", s.Account.Username, s.UUID)
	cert, privateKey, err := s.State.ca.Generate(
		keyID,
		s.State.Config.ForceCommand,
		principals,
		s.State.Config.PermittedSourceAddresses,
	)
	if err != nil {
		s.log.Error(
			"Rejecting forward: failed to generate ssh certificate",
			zap.String("id", s.UUID),
			zap.Error(err))
		newChannel.Reject(ssh.Prohibited, "failed to generate ssh certificate")
		return
	}

	// Now we add the generated key and certificate to the users agent
	err = (*ag).Add(agent.AddedKey{
		PrivateKey:   privateKey,
		Certificate:  cert,
		LifetimeSecs: 60,
		Comment:      "temporary ssh certificate",
	})

	if err != nil {
		s.log.Error(
			"Rejecting forward: failed to add ssh key/cert to agent",
			zap.String("id", s.UUID),
			zap.Error(err))
		newChannel.Reject(ssh.Prohibited, "failed to add ssh key/cert to agent")
		return
	}

	// Finally, we're ready to find out where the client wants to go, and redirect
	//  them properly.
	var msg channelOpenDirectMsg
	ssh.Unmarshal(newChannel.ExtraData(), &msg)
	address := fmt.Sprintf("%s:%d", msg.RAddr, msg.RPort)

	// Check the whitelist first
	if s.Account.whitelistRe != nil {
		if !s.Account.whitelistRe.Match([]byte(msg.RAddr)) {
			s.log.Error(
				"Rejecting forward: does not match whitelist",
				zap.String("id", s.UUID),
				zap.String("host", msg.RAddr))
			newChannel.Reject(ssh.ConnectionFailed, "invalid permissions")
			return
		}
	}

	// Then check against blacklist
	if s.Account.blacklistRe != nil {
		if s.Account.blacklistRe.Match([]byte(msg.RAddr)) {
			s.log.Error(
				"Rejecting forward: matches blacklist",
				zap.String("id", s.UUID),
				zap.String("host", msg.RAddr))
			newChannel.Reject(ssh.ConnectionFailed, "invalid permissions")
			return
		}
	}

	for _, wp := range s.State.WebhookProviders {
		platformID := s.Account.PlatformIDs[wp.PlatformName()]
		wp.NotifySessionStart(platformID, s.Conn.User(), s.UUID, msg.RAddr, fmt.Sprintf("%s", s.Conn.RemoteAddr()))
	}

	conn, err := net.Dial("tcp", address)
	if err != nil {
		s.log.Error(
			"Rejecting forward: failed to open TCP connection to remote host",
			zap.String("id", s.UUID),
			zap.String("host", address),
			zap.Error(err))
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("error: %v", err))
		return
	}

	channel, reqs, err := newChannel.Accept()
	if err != nil {
		s.log.Error(
			"Failed to accept channel",
			zap.String("id", s.UUID),
			zap.Error(err))
		return
	}

	go ssh.DiscardRequests(reqs)
	var closer sync.Once
	closeFunc := func() {
		(*agentChan).Close()
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

func (s *SSHSession) handleChannelSession(newChannel ssh.NewChannel) {
	// First we must validate the channel
	_, agentChan, success := s.authenticateChannel(newChannel)
	if !success {
		return
	}

	channel, reqs, err := newChannel.Accept()
	if err != nil {
		s.log.Error(
			"Failed to accept channel",
			zap.String("id", s.UUID),
			zap.Error(err))
		return
	}
	defer channel.Close()
	defer (*agentChan).Close()

	for {
		req := <-reqs
		if req == nil {
			return
		}

		if req.Type == "exec" {
			msg := channelExecMsg{}
			ssh.Unmarshal(req.Payload, &msg)
			execContents := strings.SplitN(msg.Command, " ", 2)

			if command, exists := s.State.Config.Commands[execContents[0]]; exists {
				s.log.Info(
					"Running command on behalf of user",
					zap.String("command", msg.Command),
					zap.String("id", s.UUID),
				)
				if command.Type == "file" {
					if len(command.Args) != 1 {
						s.log.Error(
							"Failed to execute command due to incorrect number of arguments",
							zap.String("command", execContents[0]),
						)
						req.Reply(false, []byte("Failed to execute due to error"))
						return
					}

					filePath := command.Args[0]
					contents, err := ioutil.ReadFile(filePath)
					if err != nil {
						s.log.Error(
							"Failed to execute file command due to error",
							zap.String("path", filePath),
							zap.Error(err),
						)
						req.Reply(false, []byte("Failed to execute due to error"))
						return
					}

					channel.Write(contents)
					req.Reply(true, make([]byte, 0))
					return
				}
			}
		} else if req.Type == "shell" {
			req.Reply(false, []byte("Invalid request"))
			return
		}
	}
}
