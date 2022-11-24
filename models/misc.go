package models

type HealthResponse struct {
	TappedPods            []*PodInfo      `json:"tappedPods"`
	ConnectedTappersCount int             `json:"connectedTappersCount"`
	TappersStatus         []*TapperStatus `json:"tappersStatus"`
}

type VersionResponse struct {
	Ver string `json:"ver"`
}
