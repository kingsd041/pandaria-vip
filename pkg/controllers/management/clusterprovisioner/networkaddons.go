package clusterprovisioner

// PANDARIA: networkaddons hijack cluster provisioning process to change rke config for some extra addons

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/rancher/rancher/pkg/image"
	"github.com/rancher/rancher/pkg/settings"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
)

const (
	pluginMultusFlannel = "multus-flannel-macvlan"
	pluginMultusCanal   = "multus-canal-macvlan"
)

func (p *Provisioner) handleNetworkPlugin(old v3.ClusterSpec, clusterName string) (v3.ClusterSpec, error) {
	spec := old.DeepCopy()

	if spec.RancherKubernetesEngineConfig != nil {
		switch spec.RancherKubernetesEngineConfig.Network.Plugin {
		case pluginMultusFlannel:
			err := p.handleMultusFlannel(spec.RancherKubernetesEngineConfig, clusterName)
			return *spec, err
		case pluginMultusCanal:
			err := p.handleMultusCanal(spec.RancherKubernetesEngineConfig, clusterName)
			return *spec, err
		}
	}

	return *spec, nil
}

func (p *Provisioner) handleMultusFlannel(cfg *v3.RancherKubernetesEngineConfig, clusterName string) error {
	template := fmt.Sprintf("%s%s%s.yaml",
		os.Getenv("NETWORK_ADDONS_DIR"), string(os.PathSeparator), pluginMultusFlannel)

	if _, err := os.Stat(template); err != nil {
		logrus.Errorf("networkaddons: %v", err)
		return err
	}

	b, err := ioutil.ReadFile(template)
	if err != nil {
		logrus.Errorf("networkaddons: %v", err)
		return err
	}

	content := applyMultusFlannelOption(string(b), cfg.Network.Options)

	rkeRegistry := getDefaultRKERegistry(cfg.PrivateRegistries)
	logrus.Debugf("networkaddons: got rke registry: %s", rkeRegistry)
	if rkeRegistry != "" {
		content = resolveRKERegistry(content, rkeRegistry)
	} else {
		content = resolveSystemRegistry(content)
	}
	content = resolveControllerClusterCIDR(cfg.Services.KubeController.ClusterCIDR, content)

	path := fmt.Sprintf("%s.%s", template, clusterName)
	err = ioutil.WriteFile(path, []byte(content), 0644)
	if err != nil {
		logrus.Errorf("networkaddons: %v", err)
		return err
	}

	// rewrite network option and insert addons_include
	cfg.Network.Plugin = "none"
	if cfg.AddonsInclude == nil {
		cfg.AddonsInclude = []string{}
	}
	cfg.AddonsInclude = append([]string{path}, cfg.AddonsInclude...)

	// add certs args
	setCertsArgs(cfg)

	return nil
}

func applyMultusFlannelOption(addons string, option map[string]string) string {
	if option["flannel_iface"] != "" {
		addons = strings.Replace(addons, "# - --iface=eth0", fmt.Sprintf("- --iface=%s", option["flannel_iface"]), -1)
	}

	return addons
}

func (p *Provisioner) handleMultusCanal(cfg *v3.RancherKubernetesEngineConfig, clusterName string) error {
	template := fmt.Sprintf("%s%s%s.yaml",
		os.Getenv("NETWORK_ADDONS_DIR"), string(os.PathSeparator), pluginMultusCanal)

	if _, err := os.Stat(template); err != nil {
		logrus.Errorf("networkaddons: %v", err)
		return err
	}

	b, err := ioutil.ReadFile(template)
	if err != nil {
		logrus.Errorf("networkaddons: %v", err)
		return err
	}

	content := applyMultusCanalOption(string(b), cfg.Network.Options)

	rkeRegistry := getDefaultRKERegistry(cfg.PrivateRegistries)
	logrus.Debugf("networkaddons: got rke registry: %s", rkeRegistry)
	if rkeRegistry != "" {
		content = resolveRKERegistry(content, rkeRegistry)
	} else {
		content = resolveSystemRegistry(content)
	}
	content = resolveControllerClusterCIDR(cfg.Services.KubeController.ClusterCIDR, content)

	path := fmt.Sprintf("%s.%s", template, clusterName)
	err = ioutil.WriteFile(path, []byte(content), 0644)
	if err != nil {
		logrus.Errorf("networkaddons: %v", err)
		return err
	}

	// rewrite network option and insert addons_include
	cfg.Network.Plugin = "none"
	if cfg.AddonsInclude == nil {
		cfg.AddonsInclude = []string{}
	}
	cfg.AddonsInclude = append([]string{path}, cfg.AddonsInclude...)

	// add certs args
	setCertsArgs(cfg)

	return nil
}

func applyMultusCanalOption(addons string, option map[string]string) string {
	if option["canal_iface"] != "" {
		addons = strings.Replace(addons, "canal_iface: \"\"", fmt.Sprintf("canal_iface: \"%s\"", option["canal_iface"]), -1)
	}

	return addons
}

func replaceImage(origin string) string {
	s := strings.SplitN(origin, ":", 2)
	if len(s) != 2 {
		return origin
	}
	newImage := "image: " + image.Resolve(strings.TrimLeft(s[1], " "))
	logrus.Debugf("origin image: %s, registry prefixed image: %s", origin, newImage)
	return newImage
}

// resolveSystemRegistry find all image field in yaml content
// and replace with new image value which system registry prefixed
func resolveSystemRegistry(content string) string {
	if settings.SystemDefaultRegistry.Get() == "" {
		return content
	}
	exp := `image:.*`
	return regexp.MustCompile(exp).ReplaceAllStringFunc(content, replaceImage)
}

func getDefaultRKERegistry(registries []v3.PrivateRegistry) string {
	var registry string
	for _, reg := range registries {
		if reg.IsDefault {
			registry = reg.URL
			break
		}
	}
	return registry
}

// resolveRKERegistry can add rke registry prefix for the yaml content
func resolveRKERegistry(content, registry string) string {
	exp := `image:.*`
	return regexp.MustCompile(exp).ReplaceAllStringFunc(content, func(origin string) string {
		s := strings.SplitN(origin, ":", 2)
		if len(s) != 2 {
			return origin
		}
		oldImg := strings.TrimLeft(s[1], " ")
		if !strings.HasPrefix(oldImg, registry) {
			res := "image: " + path.Join(registry, oldImg)
			logrus.Debugf("networkaddons: %s replaced by %s", oldImg, res)
			return res
		}

		return origin
	})
}

func resolveControllerClusterCIDR(cidr, content string) string {
	if cidr == "" {
		return content
	}
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return content
	}
	if cidr != "10.42.0.0/16" {
		exp := `"Network": "10.42.0.0/16"`
		return regexp.MustCompile(exp).ReplaceAllStringFunc(content, func(origin string) string {
			s := strings.SplitN(origin, ":", 2)
			if len(s) != 2 {
				return origin
			}
			res := fmt.Sprintf(`"Network": "%s"`, cidr)
			logrus.Debugf("networkaddons: Network cidr replaced by %s", res)
			return res
		})
	}
	return content
}

// set certs args for kube-apiserver allowing admission webhook
func setCertsArgs(cfg *v3.RancherKubernetesEngineConfig) {
	setArg := func(m map[string]string, key string, value string) {
		if m[key] == "" {
			m[key] = value
		}
	}
	if cfg.Services.KubeController.ExtraArgs == nil {
		cfg.Services.KubeController.ExtraArgs = map[string]string{}
	}
	setArg(cfg.Services.KubeController.ExtraArgs, "client-ca-file", "/etc/kubernetes/ssl/kube-ca.pem")
	setArg(cfg.Services.KubeController.ExtraArgs, "cluster-signing-cert-file", "/etc/kubernetes/ssl/kube-ca.pem")
	setArg(cfg.Services.KubeController.ExtraArgs, "cluster-signing-key-file", "/etc/kubernetes/ssl/kube-ca-key.pem")
	setArg(cfg.Services.KubeController.ExtraArgs, "requestheader-client-ca-file", "/etc/kubernetes/ssl/kube-apiserver-requestheader-ca.pem")
}
