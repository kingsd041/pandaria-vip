package globaldns

import (
	"github.com/rancher/rancher/pkg/settings"

	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"k8s.io/apimachinery/pkg/runtime"
)

func (n *ProviderCatalogLauncher) handleRDNSProvider(obj *v3.GlobalDNSProvider) (runtime.Object, error) {
	rancherInstallUUID := settings.InstallUUID.Get()
	// create external-dns rdns provider
	answers := map[string]string{
		"provider":              "rdns",
		"rdns.etcd_urls":        obj.Spec.RDNSProviderConfig.ETCDUrls,
		"rdns.rdns_root_domain": obj.Spec.RootDomain,
		"txtOwnerId":            rancherInstallUUID + "_" + obj.Name,
		"rbac.create":           "true",
		"policy":                "sync",
	}

	if obj.Spec.RootDomain != "" {
		answers["domainFilters[0]"] = obj.Spec.RootDomain
	}

	return n.createUpdateExternalDNSApp(obj, answers)
}
