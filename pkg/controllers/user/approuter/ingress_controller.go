package approuter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/pkg/errors"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/ticker"
	v1 "github.com/rancher/types/apis/core/v1"
	"github.com/rancher/types/apis/extensions/v1beta1"
	"github.com/sirupsen/logrus"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/labels"

	// PANDARIA
	"github.com/rancher/rancher/pkg/controllers/user/ingress"
)

const (
	annotationIngressClass = "kubernetes.io/ingress.class"
	annotationGlobalDNS    = "rancher.io/globalDNS.hostname" // PANDARIA
	ingressClassNginx      = "nginx"
	//RdnsIPDomain           = "lb.rancher.cloud" // PANDARIA
	ingressClassExternalDNS = "rancher-external-dns" // PANDARIA
	maxHost                 = 10
)

var (
	renewInterval = 24 * time.Hour
)

type Controller struct {
	ctx                    context.Context
	ingressInterface       v1beta1.IngressInterface
	ingressLister          v1beta1.IngressLister
	managementSecretLister v1.SecretLister
	clusterName            string
	dnsClient              *Client
}

func isGeneratedDomain(obj *extensionsv1beta1.Ingress, host, domain string) bool {
	parts := strings.Split(host, ".")
	// PANDARIA
	return strings.HasSuffix(host, "."+domain) && len(parts) >= 6 && parts[1] == obj.Namespace
}

func (c *Controller) sync(key string, obj *extensionsv1beta1.Ingress) (runtime.Object, error) {
	if obj == nil || obj.DeletionTimestamp != nil {
		return nil, nil
	}

	// PANDARIA: skip rancher-server ingress
	if _, ok := obj.Annotations[ingress.IngressRServerAnnotation]; ok {
		return nil, nil
	}

	// PANDARIA
	//ipDomain := settings.IngressIPDomain.Get()
	//if ipDomain != RdnsIPDomain {
	//	return nil, nil
	//}
	isRDNS := settings.RDNSServerBaseURL.Get()
	if isRDNS == "" {
		return nil, nil
	}
	if _, ok := obj.Annotations[annotationGlobalDNS]; ok {
		logrus.Debugf("ingress %s has not valid annotations", obj.Name)
		return nil, nil
	}
	if v, ok := obj.Annotations[annotationIngressClass]; ok {
		if v == ingressClassExternalDNS {
			logrus.Debugf("ingress %s has not valid annotations", obj.Name)
			return nil, nil
		}
	}
	ipDomain := settings.IngressIPDomain.Get()

	isNeedSync := false
	for _, rule := range obj.Spec.Rules {
		// PANDARIA
		if strings.HasSuffix(rule.Host, ipDomain) {
			isNeedSync = true
			break
		}
	}

	if !isNeedSync {
		return nil, nil
	}

	serverURL := settings.RDNSServerBaseURL.Get()
	if serverURL == "" {
		return nil, errors.New("settings.baseRDNSServerURL is not set, dns name might not be reachable")
	}

	var ips []string
	for _, status := range obj.Status.LoadBalancer.Ingress {
		if status.IP != "" {
			ips = append(ips, status.IP)
		}
	}

	if len(ips) > maxHost {
		logrus.Debugf("hosts number is %d, over %d", len(ips), maxHost)
		ips = ips[:maxHost]
	}

	c.dnsClient.SetBaseURL(serverURL)

	created, fqdn, err := c.dnsClient.ApplyDomain(ips)
	if err != nil {
		logrus.WithError(err).Errorf("update fqdn [%s] to server [%s] error", fqdn, serverURL)
		return nil, err
	}
	//As a new secret is created, all the ingress obj will be updated
	if created {
		// PANDARIA
		return nil, c.refreshAll(fqdn, ipDomain)
	}
	// PANDARIA
	return c.refresh(fqdn, obj, ipDomain)
}

func (c *Controller) refresh(rootDomain string, obj *extensionsv1beta1.Ingress, ipDomain string) (*extensionsv1beta1.Ingress, error) {
	if obj == nil || obj.DeletionTimestamp != nil {
		return nil, errors.New("Got a nil ingress object")
	}

	annotations := obj.Annotations

	if annotations == nil {
		annotations = make(map[string]string)
	}

	targetHostname := ""
	switch annotations[annotationIngressClass] {
	case "": // nginx as default
		fallthrough
	case ingressClassNginx:
		targetHostname = c.getRdnsHostname(obj, rootDomain)
	default:
		return obj, nil
	}
	if targetHostname == "" {
		return obj, nil
	}

	changed := false
	for _, rule := range obj.Spec.Rules {
		if !isGeneratedDomain(obj, rule.Host, rootDomain) {
			changed = true
			break
		}
	}

	if !changed {
		return obj, nil
	}

	newObj := obj.DeepCopy()
	// Also need to update rules for hostname when using nginx
	for i, rule := range newObj.Spec.Rules {
		logrus.Debugf("Got ingress resource hostname: %s", rule.Host)
		// PANDARIA
		if strings.HasSuffix(rule.Host, ipDomain) {
			newObj.Spec.Rules[i].Host = targetHostname
		}
	}

	if _, err := c.ingressInterface.Update(newObj); err != nil {
		return obj, err
	}

	return newObj, nil
}

func (c *Controller) refreshAll(rootDomain, ipDomain string) error {
	ingresses, err := c.ingressLister.List("", labels.NewSelector())
	if err != nil {
		return err
	}
	for _, obj := range ingresses {
		// PANDARIA
		if _, ok := obj.Annotations[annotationGlobalDNS]; ok {
			logrus.Debugf("ingress %s has not valid annotations", obj.Name)
			continue
		}
		if v, ok := obj.Annotations[annotationIngressClass]; ok {
			if v == ingressClassExternalDNS {
				logrus.Debugf("ingress %s has not valid annotations", obj.Name)
				continue
			}
		}
		if _, err = c.refresh(rootDomain, obj, ipDomain); err != nil {
			logrus.WithError(err).Errorf("refresh ingress %s:%s hostname annotation error", obj.Namespace, obj.Name)
		}
	}
	return nil
}

func (c *Controller) getRdnsHostname(obj *extensionsv1beta1.Ingress, rootDomain string) string {
	if rootDomain != "" {
		return fmt.Sprintf("%s.%s.%s", obj.Name, obj.Namespace, rootDomain)
	}
	return ""
}

func (c *Controller) renew(ctx context.Context) {
	for range ticker.Context(ctx, renewInterval) {
		// PANDARIA
		//ipDomain := settings.IngressIPDomain.Get()
		//if ipDomain != RdnsIPDomain {
		//	continue
		//}
		isRDNS := settings.RDNSServerBaseURL.Get()
		if isRDNS == "" {
			continue
		}
		serverURL := settings.RDNSServerBaseURL.Get()
		if serverURL == "" {
			logrus.Warn("RDNSServerBaseURL need to be set when enable approuter controller")
			continue
		}

		c.dnsClient.SetBaseURL(serverURL)

		if fqdn, err := c.dnsClient.RenewDomain(); err != nil {
			logrus.WithError(err).Errorf("renew fqdn [%s] to server [%s] error", fqdn, serverURL)
		}
	}
}
