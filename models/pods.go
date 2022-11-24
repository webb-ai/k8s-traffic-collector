package models

import v1 "k8s.io/api/core/v1"

type TappedPodStatus struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	IsTapped  bool   `json:"isTapped"`
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
