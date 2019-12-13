package resourcequota

import (
	"encoding/json"

	namespaceutil "github.com/rancher/rancher/pkg/namespace"
	validate "github.com/rancher/rancher/pkg/resourcequota"

	"github.com/rancher/norman/types/convert"
	v1 "github.com/rancher/types/apis/core/v1"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientcache "k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/quota/v1"
)

const (
	resourceQuotaUsageAnnotation = "field.cattle.io/resourceQuotaUsage"
)

/*
UsageController is responsible for aggregate the resource quota usage,
and setting this information in the project and namespace
*/
type UsageController struct {
	ProjectLister       v3.ProjectLister
	projects            v3.ProjectInterface
	Namespaces          v1.NamespaceInterface
	NamespaceLister     v1.NamespaceLister
	ResourceQuotas      v1.ResourceQuotaInterface
	ResourceQuotaLister v1.ResourceQuotaLister
	LimitRange          v1.LimitRangeInterface
	LimitRangeLister    v1.LimitRangeLister
	NsIndexer           clientcache.Indexer
}

func (c *UsageController) syncResourceQuotaNamespaceUsage(key string, rq *corev1.ResourceQuota) (runtime.Object, error) {
	if rq == nil || rq.DeletionTimestamp != nil {
		return nil, nil
	}

	return nil, c.syncNamespaceUsage(rq)
}

func (c *UsageController) syncResourceQuotaProjectUsage(key string, ns *corev1.Namespace) (runtime.Object, error) {
	if ns == nil {
		return nil, nil
	}

	return nil, c.syncProjectUsage(ns)
}

func (c *UsageController) syncProjectUsage(ns *corev1.Namespace) error {
	set, err := namespaceutil.IsNamespaceConditionSet(ns, ResourceQuotaInitCondition, true)
	if err != nil || !set {
		return err
	}

	if _, ok := ns.Annotations[resourceQuotaUsageAnnotation]; !ok {
		return nil
	}

	projectID, ok := ns.Annotations[projectIDAnnotation]
	if !ok {
		return nil
	}

	// validate resource quota
	mu := validate.GetProjectLock(projectID)
	mu.Lock()
	defer mu.Unlock()

	projectNamespace, projectName := getProjectNamespaceName(projectID)
	project, err := c.ProjectLister.Get(projectNamespace, projectName)
	if err != nil || project.Spec.ResourceQuota == nil {
		return err
	}

	namespaces, err := c.NsIndexer.ByIndex(nsByProjectIndex, projectID)
	if err != nil {
		return err
	}

	nssResourceList := corev1.ResourceList{}

	for _, obj := range namespaces {
		n := obj.(*corev1.Namespace)

		if n.DeletionTimestamp != nil {
			continue
		}

		// skip itself
		if projectNamespace == n.Name {
			continue
		}

		set, err := namespaceutil.IsNamespaceConditionSet(n, ResourceQuotaInitCondition, true)
		if err != nil || !set {
			continue
		}

		val, ok := n.Annotations[resourceQuotaUsageAnnotation]
		if !ok {
			continue
		}

		nsLimit := &v3.ResourceQuotaLimit{}
		err = json.Unmarshal([]byte(convert.ToString(val)), nsLimit)
		if err != nil {
			return err
		}

		nsResourceList, err := validate.ConvertLimitToResourceList(nsLimit)
		if err != nil {
			return err
		}

		nssResourceList = quota.Add(nssResourceList, nsResourceList)
	}

	usage, err := convertResourceListToLimit(nssResourceList)
	if err != nil {
		return err
	}

	b, err := json.Marshal(usage)
	if err != nil {
		return err
	}

	if string(b) == getProjectResourceQuotaUsage(project) {
		return nil
	}

	updatedProject := project.DeepCopy()
	if updatedProject.Annotations == nil {
		updatedProject.Annotations = map[string]string{}
	}

	updatedProject.Annotations[resourceQuotaUsageAnnotation] = string(b)

	_, err = c.projects.Update(updatedProject)
	if err != nil {
		return err
	}

	return nil
}

func (c *UsageController) syncNamespaceUsage(rq *corev1.ResourceQuota) error {
	if v, ok := rq.Labels[resourceQuotaLabel]; !ok || v != "true" {
		return nil
	}

	if rq.Namespace == "" {
		return nil
	}

	ns, err := c.NamespaceLister.Get("", rq.Namespace)
	if err != nil || ns == nil {
		return err
	}

	set, err := namespaceutil.IsNamespaceConditionSet(ns, ResourceQuotaInitCondition, true)
	if err != nil || !set {
		return err
	}

	rq, err = c.getExistingResourceQuota(ns)
	if err != nil {
		return err
	}

	resourceQuota := rq

	usage, err := convertUsageToResourceLimit(resourceQuota.Status.Used)
	if err != nil {
		return err
	}

	b, err := json.Marshal(usage)
	if err != nil {
		return err
	}

	if string(b) == getNamespaceResourceQuotaUsage(ns) {
		return nil
	}

	updatedNs := ns.DeepCopy()
	if updatedNs.Annotations == nil {
		updatedNs.Annotations = map[string]string{}
	}

	updatedNs.Annotations[resourceQuotaUsageAnnotation] = string(b)

	_, err = c.Namespaces.Update(updatedNs)
	if err != nil {
		return err
	}

	return nil
}

func (c *UsageController) getExistingResourceQuota(ns *corev1.Namespace) (*corev1.ResourceQuota, error) {
	set := labels.Set(map[string]string{resourceQuotaLabel: "true"})
	quota, err := c.ResourceQuotaLister.List(ns.Name, set.AsSelector())
	if err != nil {
		return nil, err
	}
	if len(quota) == 0 {
		return nil, nil
	}
	return quota[0], nil
}

func getNamespaceResourceQuotaUsage(ns *corev1.Namespace) string {
	if ns.Annotations == nil {
		return ""
	}
	return ns.Annotations[resourceQuotaUsageAnnotation]
}

func convertUsageToResourceLimit(rList corev1.ResourceList) (*v3.ResourceQuotaLimit, error) {
	result := &corev1.ResourceList{}
	assemble := corev1.ResourceList{}

	for k, v := range resourceQuotaConversion {
		if val, ok := rList[corev1.ResourceName(v)]; ok {
			assemble[corev1.ResourceName(k)] = val
		}
	}

	for k, v := range rList {
		if k == "pods" || k == "services" || k == "secrets" {
			assemble[corev1.ResourceName(k)] = v
		}
	}

	bytes, err := json.Marshal(assemble)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(bytes, result)
	if err != nil {
		return nil, err
	}

	return convertResourceListToLimit(*result)
}

func getProjectResourceQuotaUsage(p *v3.Project) string {
	if p.Annotations == nil {
		return ""
	}
	return p.Annotations[resourceQuotaUsageAnnotation]
}
