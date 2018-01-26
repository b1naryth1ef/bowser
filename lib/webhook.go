package bowser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
	if err == nil {
		resp.Body.Close()
	}

	return err
}

func (d DiscordWebhookProvider) NotifySessionStart(platformID, username, sessionID, proxyHost, sourceHost string) error {
	var desc []string

	if platformID != "" {
		desc = append(desc, fmt.Sprintf("**User:** <@%s>", platformID))
	} else {
		desc = append(desc, fmt.Sprintf("**User:** %s", username))
	}

	desc = append(desc, fmt.Sprintf("**Host:** %s", proxyHost))
	desc = append(desc, fmt.Sprintf("**Source:** %s", sourceHost))
	desc = append(desc, fmt.Sprintf("**Session:** %s", sessionID))

	return d.send(MessagePayload{Embeds: []Embed{Embed{
		Title:       fmt.Sprintf("%s@%s", username, proxyHost),
		Description: strings.Join(desc, "\n"),
		Color:       7855479,
	}}})
}
