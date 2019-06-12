package kubectl

import (
	"fmt"
	"io/ioutil"
	"os/exec"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func Copy(namespace, pod, container, path string, kubeConfig *clientcmdapi.Config) ([]byte, error) {
	if container == "" {
		container = pod
	}

	kubeConfigFile, err := writeKubeConfig(kubeConfig)
	defer cleanup(kubeConfigFile)
	if err != nil {
		return nil, err
	}

	tmpFile, err := tempFile("podfile-")
	if err != nil {
		return nil, err
	}
	defer cleanup(tmpFile)

	cmd := exec.Command("kubectl",
		"--kubeconfig",
		kubeConfigFile.Name(),
		"cp",
		namespace+"/"+pod+":"+path,
		tmpFile.Name(),
		"-c",
		container)

	b, err := runWithHTTP2(cmd)
	if err != nil {
		return nil, fmt.Errorf("%v :%s", err, string(b))
	}

	b, err = ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, err
	}

	return b, nil
}
