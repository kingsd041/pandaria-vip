package clusterprovisioner

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/rancher/rancher/pkg/image"
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
		logrus.Error(err)
		return err
	}

	b, err := ioutil.ReadFile(template)
	if err != nil {
		logrus.Error(err)
		return err
	}

	content := applyMultusFlannelOption(string(b), cfg.Network.Options)
	content = resolveSystemRegistry(content)
	path := fmt.Sprintf("%s.%s", template, clusterName)
	err = ioutil.WriteFile(path, []byte(content), 0644)
	if err != nil {
		logrus.Error(err)
		return err
	}

	// rewrite network option and insert addons_include
	cfg.Network.Plugin = "none"
	if cfg.AddonsInclude == nil {
		cfg.AddonsInclude = []string{}
	}
	cfg.AddonsInclude = append([]string{path}, cfg.AddonsInclude...)
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
		logrus.Error(err)
		return err
	}

	b, err := ioutil.ReadFile(template)
	if err != nil {
		logrus.Error(err)
		return err
	}

	content := applyMultusCanalOption(string(b), cfg.Network.Options)
	content = resolveSystemRegistry(content)
	path := fmt.Sprintf("%s.%s", template, clusterName)
	err = ioutil.WriteFile(path, []byte(content), 0644)
	if err != nil {
		logrus.Error(err)
		return err
	}

	// rewrite network option and insert addons_include
	cfg.Network.Plugin = "none"
	if cfg.AddonsInclude == nil {
		cfg.AddonsInclude = []string{}
	}
	cfg.AddonsInclude = append([]string{path}, cfg.AddonsInclude...)
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
	logrus.Infof("origin image: %s, registry prefixed image: %s", origin, newImage)
	return newImage
}

// resolveSystemRegistry find all image field in yaml content
// and replace with new image value which system registry prefixed
func resolveSystemRegistry(content string) string {
	exp := `image:.*`
	return regexp.MustCompile(exp).ReplaceAllStringFunc(content, replaceImage)
}
