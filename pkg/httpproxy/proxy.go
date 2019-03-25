package httpproxy

import (
	"fmt"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/types/apis/core/v1"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
)

const (
	ForwardProto = "X-Forwarded-Proto"
	APIAuth      = "X-API-Auth-Header"
	CattleAuth   = "X-API-CattleAuth-Header"
	AuthHeader   = "Authorization"

	HarborAdminHeader   = "X-API-Harbor-Admin-Header"
	HarborAccountHeader = "X-API-Harbor-Account-Header"

	HarborUserAnnotationAuth = "authz.management.cattle.io.cn/harborauth"
)

var (
	httpStart  = regexp.MustCompile("^http:/([^/])")
	httpsStart = regexp.MustCompile("^https:/([^/])")
	badHeaders = map[string]bool{
		"host":                    true,
		"transfer-encoding":       true,
		"content-length":          true,
		"x-api-auth-header":       true,
		"x-api-cattleauth-header": true,
		"cf-connecting-ip":        true,
		"cf-ray":                  true,
		"impersonate-user":        true,
		"impersonate-group":       true,
	}
)

type Supplier func() []string

type proxy struct {
	prefix             string
	validHostsSupplier Supplier
	credentials        v1.SecretInterface
}

func (p *proxy) isAllowed(host string) bool {
	for _, valid := range p.validHostsSupplier() {
		if valid == host {
			return true
		}

		if strings.HasPrefix(valid, "*") && strings.HasSuffix(host, valid[1:]) {
			return true
		}
	}

	return false
}

func NewProxy(prefix string, validHosts Supplier, scaledContext *config.ScaledContext) http.Handler {
	p := proxy{
		prefix:             prefix,
		validHostsSupplier: validHosts,
		credentials:        scaledContext.Core.Secrets(""),
	}

	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			if err := p.proxy(req); err != nil {
				logrus.Infof("Failed to proxy %v: %v", req, err)
			}
		},
	}
}

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
	}
}

func (p *proxy) proxy(req *http.Request) error {
	path := req.URL.String()
	index := strings.Index(path, p.prefix)
	destPath := path[index+len(p.prefix):]

	if httpsStart.MatchString(destPath) {
		destPath = httpsStart.ReplaceAllString(destPath, "https://$1")
	} else if httpStart.MatchString(destPath) {
		destPath = httpStart.ReplaceAllString(destPath, "http://$1")
	} else {
		destPath = "https://" + destPath
	}

	destURL, err := url.Parse(destPath)
	if err != nil {
		return err
	}

	destURL.RawQuery = req.URL.RawQuery

	if !p.isAllowed(destURL.Host) {
		return fmt.Errorf("invalid host: %v", destURL.Host)
	}

	headerCopy := http.Header{}

	if req.TLS != nil {
		headerCopy.Set(ForwardProto, "https")
	}
	auth := req.Header.Get(APIAuth)
	cAuth := req.Header.Get(CattleAuth)
	for name, value := range req.Header {
		if badHeaders[strings.ToLower(name)] {
			continue
		}

		copy := make([]string, len(value))
		for i := range value {
			copy[i] = strings.TrimPrefix(value[i], "rancher:")
		}
		headerCopy[name] = copy
	}

	req.Host = destURL.Hostname()
	req.URL = destURL
	req.Header = headerCopy

	if auth != "" { // non-empty AuthHeader is noop
		req.Header.Set(AuthHeader, auth)
	} else if cAuth != "" {
		// setting CattleAuthHeader will replace credential id with secret data
		// and generate signature
		signer := newSigner(cAuth)
		if signer != nil {
			return signer.sign(req, p.credentials, cAuth)
		}
		req.Header.Set(AuthHeader, cAuth)
	}

	return nil
}
