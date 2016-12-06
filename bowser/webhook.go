package bowser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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
	NotifyNewSession(username, host string) error
}

type DiscordWebhookProvider struct {
	URL string
}

func (d DiscordWebhookProvider) NotifyNewSession(username, host string) error {
	data, err := json.Marshal(MessagePayload{Embeds: []Embed{Embed{
		Title:       "New SSH Session",
		Description: fmt.Sprintf("%s started a new session on %s", username, host),
		Color:       7855479,
	}}})

	if err != nil {
		return err
	}

	log.Printf("data: %s", data)

	req, err := http.NewRequest("POST", d.URL, bytes.NewBuffer(data))

	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("out: %s", body)

	return err
}
