package rbac

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/rancher/norman/types/slice"
	"github.com/rancher/rancher/pkg/ticker"
	mgmtclient "github.com/rancher/types/client/management/v3"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type saicRTBWatcher struct {
	cluster *config.UserContext
}

func StartRTBWatcher(ctx context.Context, cluster *config.UserContext) {
	s := &saicRTBWatcher{
		cluster: cluster,
	}

	go s.watch(ctx, 3600*time.Second)
}

func (s *saicRTBWatcher) watch(ctx context.Context, interval time.Duration) {
	for range ticker.Context(ctx, interval) {
		if err := s.checkProjectRole(); err != nil {
			logrus.Errorf("sync role on cluster %s error: %v", s.cluster.ClusterName, err)
		}
	}
}

func (s *saicRTBWatcher) checkProjectRole() error {
	clusterName := s.cluster.ClusterName
	roleList, err := s.cluster.RBAC.Roles(clusterName).List(metav1.ListOptions{})
	if err != nil || len(roleList.Items) == 0 {
		return err
	}

	// only check project role of project-owner,
	// forbidden update verbs of project-owner
	for _, pr := range roleList.Items {
		owners := pr.OwnerReferences
		if len(owners) > 0 {
			if strings.ToLower(owners[0].Kind) == mgmtclient.ProjectType && pr.Name == fmt.Sprintf("%s-projectowner", owners[0].Name) {
				updateRole := pr.DeepCopy()
				if slice.ContainsString(updateRole.Rules[0].Verbs, "*") {
					updateRole.Rules[0].Verbs = []string{"get", "list", "watch"}
				}
				if !reflect.DeepEqual(pr, *updateRole) {
					_, err = s.cluster.RBAC.Roles(clusterName).Update(updateRole)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}
