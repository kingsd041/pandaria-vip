package gpusharing

import (
	"net/http"

	"github.com/gorilla/mux"
)

const (
	policyConfig       = "schedulerpolicyconfig"
	rkeSchedulerConfig = "rkeschedulerconfig"
)

func TemplateHandler(resp http.ResponseWriter, req *http.Request) {
	template := mux.Vars(req)["template"]

	switch template {
	case policyConfig:
		resp.Header().Set("Content-Type", "text/plain")
		resp.Write([]byte(schedulerPolicyConfig))
	case rkeSchedulerConfig:
		resp.Header().Set("Content-Type", "application/json")
		resp.Write([]byte(rkeSchedulerConfigTemplate))
	default:
		resp.WriteHeader(404)
		return
	}
}

var (
	schedulerPolicyConfig = `{
  "kind": "Policy",
  "apiVersion": "v1",
  "extenders": [
    {
      "urlPrefix": "http://127.0.0.1:_NODEPORT_/gpushare-scheduler",
      "filterVerb": "filter",
      "bindVerb":   "bind",
      "enableHttps": false,
      "nodeCacheCapable": true,
      "managedResources": [
        {
          "name": "rancher.io/gpu-mem",
          "ignoredByScheduler": false
        }
      ],
      "ignorable": false
    }
  ]
}
`
	rkeSchedulerConfigTemplate = `
{
    "scheduler": {
        "extraArgs": {
            "policy-config-file": "/etc/gpushare/scheduler-policy-config.json"
        },
        "extraBinds": [
            "/etc/gpushare/scheduler-policy-config.json:/etc/gpushare/scheduler-policy-config.json"
	    ]
    }
}
`
)
