package bowser

import (
	"crypto/rand"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"strings"
	"time"
)

// CertificateAuthority represents an SSH CA that can generate/sign SSH user certificates
type CertificateAuthority struct {
	signer ssh.Signer
}

// Create a new CertificateAuthority from a CA key (generated with ssh-keygen -t rsa)
func NewCertificateAuthority(keyPath string) (ca *CertificateAuthority, err error) {
	rawKeyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return
	}

	signer, err := ssh.ParsePrivateKey(rawKeyData)
	if err != nil {
		return
	}

	ca = &CertificateAuthority{
		signer: signer,
	}

	return
}

// Generate a new ed25519 keypair and SSH user certificate, then sign with our CA private key
func (ca *CertificateAuthority) Generate(keyID, command string, validPrincipals, sourceAddresses []string) (*ssh.Certificate, *ed25519.PrivateKey, error) {
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := ssh.NewPublicKey(edPublicKey)
	if err != nil {
		return nil, nil, err
	}

	cert := ssh.Certificate{
		Key:             publicKey,
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: validPrincipals,
		ValidAfter:      uint64(time.Now().UTC().Add(-15 * time.Second).Unix()),
		ValidBefore:     uint64(time.Now().UTC().Add(1 * time.Minute).Unix()),
	}

	// These are required to be set, even if they are unused
	cert.Extensions = map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}

	cert.CriticalOptions = map[string]string{}

	// If command is passed, add it to our critical options
	if command != "" {
		cert.CriticalOptions["force-command"] = command
	}

	// If a list of source addresses was provided, add them to critical options
	if len(sourceAddresses) > 0 {
		cert.CriticalOptions["source-address"] = strings.Join(sourceAddresses, ",")
	}

	cert.SignCert(rand.Reader, ca.signer)
	return &cert, &edPrivateKey, nil
}
