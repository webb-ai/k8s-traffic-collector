package models

import basenine "github.com/up9inc/basenine/client/go"

type EntriesRequest struct {
	LeftOff   string `form:"leftOff" validate:"required"`
	Direction int    `form:"direction" validate:"required,oneof='1' '-1'"`
	Query     string `form:"query"`
	Limit     int    `form:"limit" validate:"required,min=1"`
	TimeoutMs int    `form:"timeoutMs" validate:"min=1"`
}

type SingleEntryRequest struct {
	Query string `form:"query"`
}

type EntriesResponse struct {
	Data []interface{}      `json:"data"`
	Meta *basenine.Metadata `json:"meta"`
}
