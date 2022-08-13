package models

// Message is response body for success messages
type Message struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
