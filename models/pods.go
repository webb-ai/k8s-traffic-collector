package models

import v1 "k8s.io/api/core/v1"

type PodInfo struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	NodeName  string `json:"nodeName"`
}

type TappedPodStatus struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	IsTapped  bool   `json:"isTapped"`
}

type TapperStatus struct {
	TapperName string `json:"tapperName"`
	NodeName   string `json:"nodeName"`
	Status     string `json:"status"`
}

type NodeToPodsMap map[string][]v1.Pod

func (np NodeToPodsMap) Summary() map[string][]string {
	summary := make(map[string][]string)
	for node, pods := range np {
		for _, pod := range pods {
			summary[node] = append(summary[node], pod.Namespace+"/"+pod.Name)
		}
	}

	return summary
}

func CreateWebSocketStatusMessage(tappedPodsStatus []TappedPodStatus) WebSocketStatusMessage {
	return WebSocketStatusMessage{
		WebSocketMessageMetadata: &WebSocketMessageMetadata{
			MessageType: WebSocketMessageTypeUpdateStatus,
		},
		TappingStatus: tappedPodsStatus,
	}
}

func CreateWebSocketTappedPodsMessage(nodeToTappedPodMap NodeToPodsMap) WebSocketTappedPodsMessage {
	return WebSocketTappedPodsMessage{
		WebSocketMessageMetadata: &WebSocketMessageMetadata{
			MessageType: WebSocketMessageTypeUpdateTappedPods,
		},
		NodeToTappedPodMap: nodeToTappedPodMap,
	}
}
