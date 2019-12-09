package monitoring

import (
	"strings"

	managementv3 "github.com/rancher/types/apis/management.cattle.io/v3"
)

var (
	preDefinedClusterGPUGraph   = getPredefinedClusterGPUGraph()
	preDefinedClusterGPUMetrics = getPredefinedClusterGPUMetrics()
)

func getPredefinedClusterGPUMetrics() []*managementv3.MonitorMetric {
	yamls := strings.Split(GPUMonitorMetricsTemplate, "\n---\n")
	var rtn []*managementv3.MonitorMetric
	for _, yml := range yamls {
		var tmp managementv3.MonitorMetric
		if err := yamlToObject(yml, &tmp); err != nil {
			panic(err)
		}
		if tmp.Name == "" {
			continue
		}
		rtn = append(rtn, &tmp)
	}

	return rtn
}

func getPredefinedClusterGPUGraph() []*managementv3.ClusterMonitorGraph {
	yamls := strings.Split(ClusterGPUMetricExpression, "\n---\n")
	var rtn []*managementv3.ClusterMonitorGraph
	for _, yml := range yamls {
		var tmp managementv3.ClusterMonitorGraph
		if err := yamlToObject(yml, &tmp); err != nil {
			panic(err)
		}
		if tmp.Name == "" {
			continue
		}
		rtn = append(rtn, &tmp)
	}

	return rtn
}

var (
	ClusterGPUMetricExpression = `
---
apiVersion: management.cattle.io/v3
kind: ClusterMonitorGraph
metadata:
  labels:
    app: metric-expression
    source: rancher-monitoring
    level: cluster
    component: cluster
  name: cluster-gpu-memory-usage
spec:
  resourceType: cluster
  priority: 110
  title: cluster-gpu-memory-usage
  metricsSelector:
    details: "false"
    component: cluster
    metric: gpu-memory-usage-percent
  detailsMetricsSelector:
    details: "true"
    component: cluster
    metric: gpu-memory-usage-percent
  yAxis:
    unit: percent
---
apiVersion: management.cattle.io/v3
kind: ClusterMonitorGraph
metadata:
  labels:
    app: metric-expression
    source: rancher-monitoring
    level: cluster
    component: node
  name: node-gpu-memory-usage
spec:
  resourceType: node
  priority: 510
  title: node-gpu-memory-usage
  metricsSelector:
    details: "false"
    component: node
    metric: gpu-memory-usage-percent
  detailsMetricsSelector:
    details: "true"
    component: node
    metric: gpu-memory-usage-percent
  yAxis:
    unit: percent
---
`

	GPUMonitorMetricsTemplate = `
---
kind: MonitorMetric
apiVersion: management.cattle.io/v3
metadata:
  name: cluster-gpu-memory-usage-percent
  labels:
    app: metric-expression
    component: cluster
    details: "false"
    level: cluster
    metric: gpu-memory-usage-percent
    source: rancher-monitoring
spec:
  expression: sum(dcgm_fb_used) 
    / sum(dcgm_fb_free + dcgm_fb_used)
  legendFormat: GPU Memory usage
  description: cluster gpu memory usage percent
---
kind: MonitorMetric
apiVersion: management.cattle.io/v3
metadata:
  name: cluster-gpu-memory-usage-percent-details
  labels:
    app: metric-expression
    component: cluster
    details: "true"
    level: cluster
    metric: gpu-memory-usage-percent
    source: rancher-monitoring
spec:
  expression: sum(dcgm_fb_used) by (instance)
    / sum(dcgm_fb_free + dcgm_fb_used) by (instance)
  legendFormat: '[[instance]]'
  description: cluster gpu memory usage percent
---
kind: MonitorMetric
apiVersion: management.cattle.io/v3
metadata:
  name: node-gpu-memory-usage-percent
  labels:
    app: metric-expression
    component: node
    details: "false"
    level: cluster
    metric: gpu-memory-usage-percent
    source: rancher-monitoring
spec:
  expression: sum(dcgm_fb_used{instance=~"$instance"}) by (gpu)
    / sum(dcgm_fb_used{instance=~"$instance"} + dcgm_fb_free{instance=~"$instance"}) by (gpu)
  legendFormat: GPU([[gpu]])
  description: node gpu memory usage percent
---
kind: MonitorMetric
apiVersion: management.cattle.io/v3
metadata:
  name: node-gpu-memory-usage-percent-details
  labels:
    app: metric-expression
    component: node
    details: "true"
    level: cluster
    metric: gpu-memory-usage-percent
    source: rancher-monitoring
spec:
  expression: sum(dcgm_fb_used{instance=~"$instance"}) by (gpu)
    / sum(dcgm_fb_used{instance=~"$instance"} + dcgm_fb_free{instance=~"$instance"}) by (gpu)
  legendFormat: GPU([[gpu]])
  description: node gpu memory usage percent
---
`
)
