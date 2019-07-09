package app

import (
	"github.com/rancher/types/config"
)

const (
	pandariaLibraryURL    = "https://github.com/cnrancher/pandaria-catalog"
	pandariaLibraryBranch = "master"
	pandariaLibraryName   = "pandaria"
)

func syncPandariaCatalogs(management *config.ManagementContext) error {
	return doAddCatalogs(management, pandariaLibraryName, pandariaLibraryURL, pandariaLibraryBranch)
}
