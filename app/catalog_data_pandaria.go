package app

import (
	"os"

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
	return doAddCatalogs(management, pandariaLibraryName, pandariaLibraryURL, desiredDefaultBranch)
}
