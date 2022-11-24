package models

type ToastMessage struct {
	Type      string `json:"type"`
	AutoClose uint   `json:"autoClose"`
	Text      string `json:"text"`
}
