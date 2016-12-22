package bowser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type MessagePayload struct {
	Embeds []Embed `json:"embeds"`
}

type Embed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Color       uint   `json:"color"`
}

type WebhookProvider interface {
	NotifySessionStart(username, sessionID, proxyHost, sourceHost string) error
	NotifySessionEnd(username, sessionID, proxyHost, sourceHost string) error
}

type DiscordWebhookProvider struct {
	URL string
}

func (d DiscordWebhookProvider) send(payload MessagePayload) (err error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", d.URL, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	defer resp.Body.Close()
	return err
}

func (d DiscordWebhookProvider) NotifySessionStart(username, sessionID, proxyHost, sourceHost string) error {
	return d.send(MessagePayload{Embeds: []Embed{Embed{
		Title: fmt.Sprintf("SSH session started by %s", username),
		Description: fmt.Sprintf(
			"**Host:** %s\n**Source:** %s\n**Session:** `%s`\n",
			proxyHost,
			sourceHost,
			sessionID,
		),
		Color: 7855479,
	}}})
}

func (d DiscordWebhookProvider) NotifySessionEnd(username, sessionID, proxyHost, sourceHost string) error {
	return d.send(MessagePayload{Embeds: []Embed{Embed{
		Title: fmt.Sprintf("SSH session ended by %s", username),
		Description: fmt.Sprintf(
			"**Host:** %s\n**Source:** %s\n**Session:** `%s`\n",
			proxyHost,
			sourceHost,
			sessionID,
		),
		Color: 16738657,
	}}})
}
