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
	NotifySessionStart(platformID, username, sessionID, proxyHost, sourceHost string) error
	PlatformName() string
}

type DiscordWebhookProvider struct {
	URL string
}

func (d DiscordWebhookProvider) PlatformName() string {
	return "discord"
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

func (d DiscordWebhookProvider) NotifySessionStart(platformID, username, sessionID, proxyHost, sourceHost string) error {
	var title string

	if platformID != "" {
		title = fmt.Sprintf("<@%s>@%s", platformID, proxyHost)
	} else {
		title = fmt.Sprintf("%s@%s", username, proxyHost)
	}

	return d.send(MessagePayload{Embeds: []Embed{Embed{
		Title: title,
		Description: fmt.Sprintf(
			"**User:** %s\n**Host:** %s\n**Source:** %s\n**Session:** `%s`\n",
			username,
			proxyHost,
			sourceHost,
			sessionID,
		),
		Color: 16738657,
	}}})
}
