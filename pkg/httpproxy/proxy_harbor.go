package httpproxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	HarborAdminHeader   = "X-API-Harbor-Admin-Header"
	HarborAccountHeader = "X-API-Harbor-Account-Header"

	HarborUserAnnotationAuth = "authz.management.cattle.io.cn/harborauth"
)

func NewHarborProxy(prefix string, validHosts Supplier, scaledContext *config.ScaledContext) http.Handler {
	p := proxy{
		prefix:             prefix,
		validHostsSupplier: validHosts,
		credentials:        scaledContext.Core.Secrets(""),
	}
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			harborAuth := ""
			// header for login check
			accountHeader := req.Header.Get(HarborAccountHeader)
			if accountHeader != "" {
				harborAuth = accountHeader
			} else {
				// get admin auth header
				adminHeader := req.Header.Get(HarborAdminHeader)
				if adminHeader == "true" {
					harborAuth = settings.HarborAdminAuth.Get()
				} else {
					// get harbor user auth by rancher user
					userID := req.Header.Get("Impersonate-User")
					logrus.Infoln(req.Header)
					user, err := scaledContext.Management.Users("").Get(userID, metav1.GetOptions{})
					if err != nil {
						logrus.Infof("Failed to get user %v: %v", req, err)
					}
					harborAuth = user.Annotations[HarborUserAnnotationAuth]
				}
			}
			req.Header.Set(APIAuth, fmt.Sprintf("Basic %s", harborAuth))
			if err := p.proxy(req); err != nil {
				logrus.Infof("Failed to proxy %v: %v", req, err)
			}
		},
		ModifyResponse: setModifiedHeaders,
	}
}
