package resolver

import (
	"io/ioutil"
	"os"
	"strings"
)

const defaultNamespace string = "kubeshark"
const allNamespaces string = ""

func getSelfNamespace() string {
	// This way assumes you've set the POD_NAMESPACE environment variable using the downward API.
	// This check has to be done first for backwards compatibility with the way InClusterConfig was originally set up
	if ns, ok := os.LookupEnv("POD_NAMESPACE"); ok {
		if ns == defaultNamespace {
			return allNamespaces
		}
		return ns
	}

	// Fall back to the namespace associated with the service account token, if available
	if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			if ns == defaultNamespace {
				return allNamespaces
			}
			return ns
		}
	}

	return "default"
}
