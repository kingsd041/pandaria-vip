package resourcequota

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rancher/norman/types/convert"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/cache"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/quota"
)

var (
	projectLockCache = cache.NewLRUExpireCache(1000)
)

func GetProjectLock(projectID string) *sync.Mutex {
	val, ok := projectLockCache.Get(projectID)
	if !ok {
		projectLockCache.Add(projectID, &sync.Mutex{}, time.Hour)
		val, _ = projectLockCache.Get(projectID)
	}
	mu := val.(*sync.Mutex)
	return mu
}

func IsQuotaFit(nsLimit *v3.ResourceQuotaLimit, nsLimits []*v3.ResourceQuotaLimit, projectLimit *v3.ResourceQuotaLimit) (bool, string, error) {
	nssResourceList := api.ResourceList{}
	nsResourceList, err := ConvertLimitToResourceList(nsLimit)
	if err != nil {
		return false, "", err
	}
	nssResourceList = quota.Add(nssResourceList, nsResourceList)

	for _, nsLimit := range nsLimits {
		nsResourceList, err := ConvertLimitToResourceList(nsLimit)
		if err != nil {
			return false, "", err
		}
		nssResourceList = quota.Add(nssResourceList, nsResourceList)
	}

	projectResourceList, err := ConvertLimitToResourceList(projectLimit)
	if err != nil {
		return false, "", err
	}

	allowed, exceeded := quota.LessThanOrEqual(nssResourceList, projectResourceList)
	if allowed {
		return true, "", nil
	}
	failedHard := quota.Mask(nssResourceList, exceeded)
	return false, prettyPrint(failedHard), nil
}

func ConvertLimitToResourceList(limit *v3.ResourceQuotaLimit) (api.ResourceList, error) {
	toReturn := api.ResourceList{}
	converted, err := convert.EncodeToMap(limit)
	if err != nil {
		return nil, err
	}
	for key, value := range converted {
		q, err := resource.ParseQuantity(convert.ToString(value))
		if err != nil {
			return nil, err
		}
		toReturn[api.ResourceName(key)] = q
	}
	return toReturn, nil
}

func prettyPrint(item api.ResourceList) string {
	parts := []string{}
	keys := []string{}
	for key := range item {
		keys = append(keys, string(key))
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := item[api.ResourceName(key)]
		constraint := key + "=" + value.String()
		parts = append(parts, constraint)
	}
	return strings.Join(parts, ",")
}

func IsProjectQuotaFitCluster(projectLimit *v3.ResourceQuotaLimit, clusterLimit *v3.ResourceQuotaLimit) (bool, string, error) {
	psResourceList := api.ResourceList{}
	pResourceList, err := ConvertLimitToResourceList(projectLimit)
	if err != nil {
		return false, "", err
	}
	psResourceList = quota.Add(psResourceList, pResourceList)

	clusterResourceList, err := ConvertLimitToResourceList(clusterLimit)
	if err != nil {
		return false, "", err
	}

	allowed, exceeded := QuotaLessThanOrEqual(psResourceList, clusterResourceList)
	if allowed {
		return true, "", nil
	}
	failedHard := quota.Mask(psResourceList, exceeded)
	return false, prettyPrint(failedHard), nil
}

// QuotaLessThanOrEqual returns true if a < b for each key in b
// If false, it returns the keys in a that exceeded b
func QuotaLessThanOrEqual(a api.ResourceList, b api.ResourceList) (bool, []api.ResourceName) {
	result := true
	resourceNames := []api.ResourceName{}
	for key, value := range b {
		if value.IsZero() {
			continue
		}
		if other, found := a[key]; found {
			if other.Cmp(value) > 0 {
				result = false
				resourceNames = append(resourceNames, key)
			}
		}
	}
	return result, resourceNames
}
