package monitoring

import (
	mgmtv3 "github.com/rancher/types/apis/management.cattle.io/v3"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ch *clusterHandler) deployGPUMetrics(cluster *mgmtv3.Cluster) error {
	clusterName := cluster.Name

	for _, metric := range preDefinedClusterGPUMetrics {
		newObj := metric.DeepCopy()
		newObj.Namespace = clusterName

		_, err := ch.app.cattleMonitorMetricClient.Create(newObj)
		if err != nil && !k8serrors.IsAlreadyExists(err) {
			return err
		}
	}

	for _, graph := range preDefinedClusterGPUGraph {
		newObj := graph.DeepCopy()
		newObj.Namespace = clusterName

		_, err := ch.app.cattleClusterGraphClient.Create(newObj)
		if err != nil && !k8serrors.IsAlreadyExists(err) {
			return err
		}
	}

	return nil
}

func (ch *clusterHandler) withdrawGPUMetrics(cluster *mgmtv3.Cluster) error {
	clusterName := cluster.Name

	for _, metric := range preDefinedClusterGPUMetrics {
		err := ch.app.cattleMonitorMetricClient.DeleteNamespaced(clusterName, metric.Name, &metav1.DeleteOptions{})
		if err != nil && !k8serrors.IsNotFound(err) {
			return err
		}
	}

	for _, graph := range preDefinedClusterGPUGraph {
		err := ch.app.cattleClusterGraphClient.DeleteNamespaced(clusterName, graph.Name, &metav1.DeleteOptions{})
		if err != nil && !k8serrors.IsNotFound(err) {
			return err
		}
	}

	return nil
}
