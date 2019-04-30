package httpproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"

	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Role struct {
	ID   string `json:"id"`
	Role string `json:"role"`
}
type UserRole struct {
	UserID      string `json:"userid"`
	GlobalRole  []Role `json:"globalRole"`
	ClusterRole []Role `json:"clusterRole"`
	ProjectRole []Role `json:"projectRole"`
}

func NewAuditlogProxy(prefix string, validHosts Supplier, scaledContext *config.ScaledContext) http.Handler {
	p := proxy{
		prefix:             prefix,
		validHostsSupplier: validHosts,
		credentials:        scaledContext.Core.Secrets(""),
	}

	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			userRole := UserRole{}
			userID := req.Header.Get("Impersonate-User")
			userRole.UserID = userID

			globalRoleBindings, err := scaledContext.Management.GlobalRoleBindings("").List(metav1.ListOptions{})
			if err != nil {
				logrus.Errorln("[AuditlogProxy] List GlobalRoleBindings err", err)
			} else {
				for _, v := range globalRoleBindings.Items {
					if v.UserName == userID {
						role := Role{
							ID:   "",
							Role: v.GlobalRoleName,
						}
						userRole.GlobalRole = append(userRole.GlobalRole, role)
					}
				}
			}

			clusterRoleBindings, err := scaledContext.Management.ClusterRoleTemplateBindings("").List(metav1.ListOptions{})
			if err != nil {
			} else {
				for _, v := range clusterRoleBindings.Items {
					if v.UserName == userID {
						role := Role{
							ID:   v.ClusterName,
							Role: v.RoleTemplateName,
						}
						userRole.ClusterRole = append(userRole.ClusterRole, role)
					}
				}
			}

			projectRoleBindings, err := scaledContext.Management.ProjectRoleTemplateBindings("").List(metav1.ListOptions{})
			if err != nil {
				logrus.Errorln("[AuditlogProxy] List ProjectRoleTemplateBindings err", err)
			} else {
				for _, v := range projectRoleBindings.Items {
					if v.UserName == userID {
						role := Role{
							ID:   v.ProjectName,
							Role: v.RoleTemplateName,
						}
						userRole.ProjectRole = append(userRole.ProjectRole, role)
					}
				}
			}

			userinfo, err := json.Marshal(userRole)
			if err != nil {
				logrus.Errorln("[AuditlogProxy] userRole json Marshal error:", err)
			}

			req.Header.Set("userinfo", string(userinfo))
			if err := p.proxy(req); err != nil {
				logrus.Errorf("[AuditlogProxy] Failed to proxy %v: %v", req, err)
			}
		},
	}
}
