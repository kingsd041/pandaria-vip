package httpproxy

import (
	"net/url"
	"os"

	"github.com/sirupsen/logrus"
)

func unescapePath(destPath string) (string, error) {
	// add for pandaria UI dev
	var err error
	if os.Getenv("PANDARIA_DEV_MODE") != "" {
		destPath, err = url.QueryUnescape(destPath)
		logrus.Infof("******* proxy url: %v ********", destPath)
		if err != nil {
			return "", err
		}
	}
	return destPath, nil
}
