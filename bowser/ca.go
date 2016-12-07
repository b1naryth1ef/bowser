package bowser

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"time"
)

type CertificateAuthority struct {
	signer ssh.Signer
}

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

func (ca *CertificateAuthority) Generate(sessionID, username string) (*ssh.Certificate, *ed25519.PrivateKey, error) {
	edPublicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
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
		KeyId:           fmt.Sprintf("%s_%s", username, sessionID),
		ValidPrincipals: []string{username},
		ValidAfter:      uint64(time.Now().UTC().Add(-15 * time.Second).Unix()),
		ValidBefore:     uint64(time.Now().UTC().Add(1 * time.Minute).Unix()),
	}

	cert.Extensions = map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}

	cert.SignCert(rand.Reader, ca.signer)
	return &cert, &privateKey, nil
}
