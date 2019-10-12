package clusterstats

import (
	"context"
	"encoding/json"

	"github.com/rancher/norman/types/convert"
	"github.com/rancher/rancher/pkg/clustermanager"
	validate "github.com/rancher/rancher/pkg/resourcequota"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/quota"
)

const (
	ClusterServiceAnnotation               = "cluster.saic.io/services"
	ClusterSecretAnnotation                = "cluster.saic.io/secrets"
	ClusterStorageAnnotation               = "cluster.saic.io/storage"
	ClusterConfigMapAnnotation             = "cluster.saic.io/configMaps"
	ClusterServiceNodePortAnnotation       = "cluster.saic.io/servicesNodePorts"
	ClusterServiceAllocatedPortAnnotation  = "cluster.saic.io/servicesAllocatedPorts"
	ClusterLoadBalancerAnnotation          = "cluster.saic.io/servicesLoadBalancers"
	ClusterPersistentVolumeClaimAnnotation = "cluster.saic.io/persistentVolumeClaims"
	ClusterReplicationControllerAnnotation = "cluster.saic.io/replicationControllers"
	ResourceQuotaAnnotation                = "field.cattle.io/resourceQuota"
	ResourceQuotaUsageAnnotation           = "field.cattle.io/resourceQuotaUsage"

	ResourceServiceNodePort      v1.ResourceName = "services.nodeports"
	ResourceServiceAllocatedPort v1.ResourceName = "services.allocatedports"
)

type SAICStatsAggregator struct {
	NodesLister    v3.NodeLister
	Clusters       v3.ClusterInterface
	ClusterManager *clustermanager.Manager
	ProjectsLister v3.ProjectLister
	Projects       v3.ProjectInterface
}

func SAICRegister(ctx context.Context, management *config.ManagementContext, clusterManager *clustermanager.Manager) {
	clustersClient := management.Management.Clusters("")
	machinesClient := management.Management.Nodes("")
	projectsClient := management.Management.Projects("")

	s := &SAICStatsAggregator{
		NodesLister:    machinesClient.Controller().Lister(),
		Clusters:       clustersClient,
		ClusterManager: clusterManager,
		ProjectsLister: projectsClient.Controller().Lister(),
		Projects:       projectsClient,
	}

	clustersClient.AddHandler(ctx, "cluster-stats", s.sync)
	machinesClient.AddHandler(ctx, "cluster-stats", s.machineChanged)
	projectsClient.AddHandler(ctx, "cluster-stats", s.projectChanged)
}

func (s *SAICStatsAggregator) sync(key string, cluster *v3.Cluster) (runtime.Object, error) {
	if cluster == nil {
		return nil, nil
	}

	return nil, s.aggregate(cluster, cluster.Name)
}

func (s *SAICStatsAggregator) aggregate(cluster *v3.Cluster, clusterName string) error {
	allMachines, err := s.NodesLister.List(cluster.Name, labels.Everything())
	if err != nil {
		return err
	}

	projects, err := s.ProjectsLister.List(cluster.Name, labels.Everything())
	if err != nil {
		return err
	}

	var machines []*v3.Node
	// only include worker nodes
	for _, m := range allMachines {
		if m.Spec.Worker && !m.Spec.InternalNodeSpec.Unschedulable {
			machines = append(machines, m)
		}
	}

	originResourceQuotaAnnotation := ""
	if _, ok := cluster.Annotations[ResourceQuotaAnnotation]; ok {
		originResourceQuotaAnnotation = cluster.Annotations[ResourceQuotaAnnotation]
	}

	originUsedResourceQuotaAnnotation := ""
	if _, ok := cluster.Annotations[ResourceQuotaUsageAnnotation]; ok {
		originResourceQuotaAnnotation = cluster.Annotations[ResourceQuotaUsageAnnotation]
	}

	origStatus := cluster.Status.DeepCopy()
	cluster = cluster.DeepCopy()

	// capacity keys
	pods, mem, cpu, service, loadBalancer, nodePort, allocatedPort, storage, configMap, pvc, rc, secret :=
		resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{},
		resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{},
		resource.Quantity{}, resource.Quantity{}
	// allocatable keys
	apods, amem, acpu, aService, aLoadBalancer, aNodePort, aAllocatedPort, aStorage, aConfigMap, aPvc, aRc, aSecret :=
		resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{},
		resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{},
		resource.Quantity{}, resource.Quantity{}
	// requested keys
	rpods, rmem, rcpu, rService, rLoadBalancer, rNodePort, rAllocatedPort, rStorage, rConfigMap, rPvc, rRc, rSecret :=
		resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{},
		resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{},
		resource.Quantity{}, resource.Quantity{}
	// limited keys
	lpods, lmem, lcpu, lService, lLoadBalancer, lNodePort, lAllocatedPort, lStorage, lConfigMap, lPvc, lRc, lSecret :=
		resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{},
		resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{}, resource.Quantity{},
		resource.Quantity{}, resource.Quantity{}

	condDisk := v1.ConditionTrue
	condMem := v1.ConditionTrue

	if v, ok := cluster.Annotations[ClusterServiceAnnotation]; ok {
		quantity, err := resource.ParseQuantity(v)
		if err != nil {
			return err
		}
		service.Add(quantity)
		aService.Add(quantity)
	}

	if v, ok := cluster.Annotations[ClusterLoadBalancerAnnotation]; ok {
		quantity, err := resource.ParseQuantity(v)
		if err != nil {
			return err
		}
		loadBalancer.Add(quantity)
		aLoadBalancer.Add(quantity)
	}

	if v, ok := cluster.Annotations[ClusterServiceNodePortAnnotation]; ok {
		quantity, err := resource.ParseQuantity(v)
		if err != nil {
			return err
		}
		nodePort.Add(quantity)
		aNodePort.Add(quantity)
	}

	if v, ok := cluster.Annotations[ClusterServiceAllocatedPortAnnotation]; ok {
		quantity, err := resource.ParseQuantity(v)
		if err != nil {
			return err
		}
		allocatedPort.Add(quantity)
		aAllocatedPort.Add(quantity)
	}

	if v, ok := cluster.Annotations[ClusterStorageAnnotation]; ok {
		quantity, err := resource.ParseQuantity(v)
		if err != nil {
			return err
		}
		storage.Add(quantity)
		aStorage.Add(quantity)
	}

	if v, ok := cluster.Annotations[ClusterConfigMapAnnotation]; ok {
		quantity, err := resource.ParseQuantity(v)
		if err != nil {
			return err
		}
		configMap.Add(quantity)
		aConfigMap.Add(quantity)
	}

	if v, ok := cluster.Annotations[ClusterPersistentVolumeClaimAnnotation]; ok {
		quantity, err := resource.ParseQuantity(v)
		if err != nil {
			return err
		}
		pvc.Add(quantity)
		aPvc.Add(quantity)
	}

	if v, ok := cluster.Annotations[ClusterReplicationControllerAnnotation]; ok {
		quantity, err := resource.ParseQuantity(v)
		if err != nil {
			return err
		}
		rc.Add(quantity)
		aRc.Add(quantity)
	}

	if v, ok := cluster.Annotations[ClusterSecretAnnotation]; ok {
		quantity, err := resource.ParseQuantity(v)
		if err != nil {
			return err
		}
		secret.Add(quantity)
		aSecret.Add(quantity)
	}

	for _, machine := range machines {
		capacity := machine.Status.InternalNodeStatus.Capacity
		if capacity != nil {
			pods.Add(*capacity.Pods())
			mem.Add(*capacity.Memory())
			cpu.Add(*capacity.Cpu())
		}
		allocatable := machine.Status.InternalNodeStatus.Allocatable
		if allocatable != nil {
			apods.Add(*allocatable.Pods())
			amem.Add(*allocatable.Memory())
			acpu.Add(*allocatable.Cpu())
		}
		requested := machine.Status.Requested
		if requested != nil {
			rpods.Add(*requested.Pods())
			rmem.Add(*requested.Memory())
			rcpu.Add(*requested.Cpu())
		}
		limits := machine.Status.Limits
		if limits != nil {
			lpods.Add(*limits.Pods())
			lmem.Add(*limits.Memory())
			lcpu.Add(*limits.Cpu())
		}

		if condDisk == v1.ConditionTrue && v3.ClusterConditionNoDiskPressure.IsTrue(machine) {
			condDisk = v1.ConditionFalse
		}
		if condMem == v1.ConditionTrue && v3.ClusterConditionNoMemoryPressure.IsTrue(machine) {
			condMem = v1.ConditionFalse
		}
	}

	resourceList := api.ResourceList{}
	resourceUsedList := api.ResourceList{}
	for _, p := range projects {
		if p.Spec.ResourceQuota != nil {
			limit := p.Spec.ResourceQuota.Limit.DeepCopy()
			if limit != nil {
				projectResourceList, err := validate.ConvertLimitToResourceList(limit)
				if err != nil {
					return err
				}
				resourceList = quota.Add(resourceList, projectResourceList)
			}
		}
		if v, ok := p.Annotations[ResourceQuotaUsageAnnotation]; ok {
			pLimit := &v3.ResourceQuotaLimit{}
			err = json.Unmarshal([]byte(convert.ToString(v)), pLimit)
			if err != nil {
				return err
			}
			projectUsedResourceList, err := validate.ConvertLimitToResourceList(pLimit)
			if err != nil {
				return err
			}

			resourceUsedList = quota.Add(resourceUsedList, projectUsedResourceList)
		}

	}

	clusterLimit, err := convertResourceListToLimit(resourceList)
	if err != nil {
		return err
	}

	b, err := json.Marshal(clusterLimit)
	if err != nil {
		return err
	}

	clusterUsedLimit, err := convertResourceListToLimit(resourceUsedList)
	if err != nil {
		return err
	}

	ub, err := json.Marshal(clusterUsedLimit)
	if err != nil {
		return err
	}

	if string(b) != getClusterResourceQuotaLimit(cluster) {
		cluster.Annotations[ResourceQuotaAnnotation] = string(b)
	}

	if string(ub) != getClusterUsedResourceQuotaLimit(cluster) {
		cluster.Annotations[ResourceQuotaUsageAnnotation] = string(ub)
	}

	if _, ok := cluster.Annotations[ResourceQuotaAnnotation]; !ok {
		cluster.Annotations[ResourceQuotaAnnotation] = ""
	}

	if _, ok := cluster.Annotations[ResourceQuotaUsageAnnotation]; !ok {
		cluster.Annotations[ResourceQuotaUsageAnnotation] = ""
	}

	cluster.Status.Capacity = v1.ResourceList{v1.ResourcePods: pods, v1.ResourceMemory: mem, v1.ResourceCPU: cpu,
		v1.ResourceServices: service, v1.ResourceServicesLoadBalancers: loadBalancer, ResourceServiceNodePort: nodePort,
		ResourceServiceAllocatedPort: allocatedPort, v1.ResourceStorage: storage, v1.ResourceConfigMaps: configMap,
		v1.ResourcePersistentVolumeClaims: pvc, v1.ResourceReplicationControllers: rc, v1.ResourceSecrets: secret}
	cluster.Status.Allocatable = v1.ResourceList{v1.ResourcePods: apods, v1.ResourceMemory: amem, v1.ResourceCPU: acpu,
		v1.ResourceServices: aService, v1.ResourceServicesLoadBalancers: aLoadBalancer, ResourceServiceNodePort: aNodePort,
		ResourceServiceAllocatedPort: aAllocatedPort, v1.ResourceStorage: aStorage, v1.ResourceConfigMaps: aConfigMap,
		v1.ResourcePersistentVolumeClaims: aPvc, v1.ResourceReplicationControllers: aRc, v1.ResourceSecrets: aSecret}
	cluster.Status.Requested = v1.ResourceList{v1.ResourcePods: rpods, v1.ResourceMemory: rmem, v1.ResourceCPU: rcpu,
		v1.ResourceServices: rService, v1.ResourceServicesLoadBalancers: rLoadBalancer, ResourceServiceNodePort: rNodePort,
		ResourceServiceAllocatedPort: rAllocatedPort, v1.ResourceStorage: rStorage, v1.ResourceConfigMaps: rConfigMap,
		v1.ResourcePersistentVolumeClaims: rPvc, v1.ResourceReplicationControllers: rRc, v1.ResourceSecrets: rSecret}
	cluster.Status.Limits = v1.ResourceList{v1.ResourcePods: lpods, v1.ResourceMemory: lmem, v1.ResourceCPU: lcpu,
		v1.ResourceServices: lService, v1.ResourceServicesLoadBalancers: lLoadBalancer, ResourceServiceNodePort: lNodePort,
		ResourceServiceAllocatedPort: lAllocatedPort, v1.ResourceStorage: lStorage, v1.ResourceConfigMaps: lConfigMap,
		v1.ResourcePersistentVolumeClaims: lPvc, v1.ResourceReplicationControllers: lRc, v1.ResourceSecrets: lSecret}
	if condDisk == v1.ConditionTrue {
		v3.ClusterConditionNoDiskPressure.True(cluster)
	} else {
		v3.ClusterConditionNoDiskPressure.False(cluster)
	}
	if condMem == v1.ConditionTrue {
		v3.ClusterConditionNoMemoryPressure.True(cluster)
	} else {
		v3.ClusterConditionNoMemoryPressure.False(cluster)
	}

	versionChanged := s.updateVersion(cluster)

	if statsChanged(origStatus, &cluster.Status) || versionChanged ||
		originResourceQuotaAnnotation != cluster.Annotations[ResourceQuotaAnnotation] ||
		originUsedResourceQuotaAnnotation != cluster.Annotations[ResourceQuotaUsageAnnotation] {
		_, err = s.Clusters.Update(cluster)
		return err
	}

	return nil
}

func (s *SAICStatsAggregator) updateVersion(cluster *v3.Cluster) bool {
	updated := false
	userContext, err := s.ClusterManager.UserContext(cluster.Name)
	if err == nil {
		callWithTimeout(func() {
			// This has the tendency to timeout
			version, err := userContext.K8sClient.Discovery().ServerVersion()
			if err == nil {
				isClusterVersionOk := cluster.Status.Version != nil
				isNewVersionOk := version != nil
				if isClusterVersionOk != isNewVersionOk ||
					(isClusterVersionOk && *cluster.Status.Version != *version) {
					cluster.Status.Version = version
					updated = true
				}
			}
		})
	}
	return updated
}

func (s *SAICStatsAggregator) machineChanged(key string, machine *v3.Node) (runtime.Object, error) {
	if machine != nil {
		s.Clusters.Controller().Enqueue("", machine.Namespace)
	}
	return nil, nil
}

func (s *SAICStatsAggregator) projectChanged(key string, project *v3.Project) (runtime.Object, error) {
	if project != nil {
		s.Clusters.Controller().Enqueue("", project.Namespace)
	}
	return nil, nil
}

func convertResourceListToLimit(rList api.ResourceList) (*v3.ResourceQuotaLimit, error) {
	converted, err := convert.EncodeToMap(rList)
	if err != nil {
		return nil, err
	}

	convertedMap := map[string]string{}
	for key, value := range converted {
		convertedMap[key] = convert.ToString(value)
	}

	toReturn := &v3.ResourceQuotaLimit{}
	err = convert.ToObj(convertedMap, toReturn)

	return toReturn, err
}

func getClusterResourceQuotaLimit(c *v3.Cluster) string {
	if c.Annotations == nil {
		return ""
	}
	return c.Annotations[ResourceQuotaAnnotation]
}

func getClusterUsedResourceQuotaLimit(c *v3.Cluster) string {
	if c.Annotations == nil {
		return ""
	}
	return c.Annotations[ResourceQuotaUsageAnnotation]
}
