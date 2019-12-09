package app

import (
	"os"
	"strings"

	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/types/config"
)

const (
	pandariaLibraryURL    = "https://github.com/cnrancher/pandaria-catalog"
	pandariaLibraryBranch = "master"
	pandariaLibraryName   = "pandaria"
)

func syncPandariaCatalogs(management *config.ManagementContext) error {
	desiredDefaultBranch := pandariaLibraryBranch

	if fromEnvBranch := os.Getenv("PANDARIA_CATALOG_DEFAULT_BRANCH"); fromEnvBranch != "" {
		desiredDefaultBranch = fromEnvBranch
	}
	var bundledMode bool
	if strings.ToLower(settings.SystemCatalog.Get()) == "bundled" {
		bundledMode = true
	}
	return doAddCatalogs(management, pandariaLibraryName, pandariaLibraryURL, desiredDefaultBranch, bundledMode)
}
