package endpoints

import (
	"encoding/json"

	workloadutil "github.com/rancher/rancher/pkg/controllers/user/workload"
	v3 "github.com/rancher/types/apis/project.cattle.io/v3"
)

func (c *WorkloadEndpointsController) convertIngressPortToEndpoint(w *workloadutil.Workload, exportIP string) ([]v3.PublicEndpoint, error) {
	var eps []v3.PublicEndpoint
	portAnnotation, ok := w.Annotations[workloadutil.SAICWorkloadPortAnnotation]
	if !ok {
		return eps, nil
	}
	var portList []workloadutil.ContainerPort
	err := json.Unmarshal([]byte(portAnnotation), &portList)
	if err != nil {
		return eps, err
	}

	for _, p := range portList {
		if p.Kind == "Ingress" {
			addresses := []string{exportIP}
			endpoint := v3.PublicEndpoint{
				NodeName:    "",
				Port:        int32(p.SourcePort),
				Addresses:   addresses,
				Protocol:    string(p.Protocol),
				ServiceName: w.Name,
				AllNodes:    false,
			}
			eps = append(eps, endpoint)
		}
	}

	return eps, nil
}
