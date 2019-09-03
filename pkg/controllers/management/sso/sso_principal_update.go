package sso

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"

	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

const (
	indexerName = "principalIndexer"
)

func Register(ctx context.Context, management *config.ManagementContext) {
	crtbInformer := management.Management.ClusterRoleTemplateBindings("").Controller().Informer()
	crtbInformer.AddIndexers(map[string]cache.IndexFunc{
		indexerName: crtbByPrincipal,
	})
	prtbInformer := management.Management.ProjectRoleTemplateBindings("").Controller().Informer()
	prtbInformer.AddIndexers(map[string]cache.IndexFunc{
		indexerName: prtbByPrincipal,
	})
	handler := &PrincipalUpdate{
		Users:     management.Management.Users(""),
		CRTBs:     management.Management.ClusterRoleTemplateBindings(""),
		PRTBs:     management.Management.ProjectRoleTemplateBindings(""),
		crtbIndex: crtbInformer.GetIndexer(),
		prtbIndex: prtbInformer.GetIndexer(),
	}
	management.Management.Users("").AddHandler(ctx, "sso-principal-update-handler", handler.sync)

}

type PrincipalUpdate struct {
	Users     v3.UserInterface
	PRTBs     v3.ProjectRoleTemplateBindingInterface
	CRTBs     v3.ClusterRoleTemplateBindingInterface
	prtbIndex cache.Indexer
	crtbIndex cache.Indexer
}

func (p *PrincipalUpdate) sync(key string, obj *v3.User) (runtime.Object, error) {
	if obj == nil || obj.DeletionTimestamp != nil {
		return obj, nil
	}
	index := -1
	for i, principalID := range obj.PrincipalIDs {
		if strings.HasPrefix(principalID, "sso_user://") {
			return obj, nil
		}
		if strings.HasPrefix(principalID, "sso://") {
			index = i
			break
		}
	}
	if index < 0 {
		return obj, nil
	}
	oldPrincipalID := obj.PrincipalIDs[index]
	newPrincipalID := "sso_user://" + strings.TrimPrefix(oldPrincipalID, "sso://")
	newObj := obj.DeepCopy()
	newObj.PrincipalIDs[index] = newPrincipalID
	updated, err := p.Users.Update(newObj)
	if err != nil {
		return nil, err
	}
	prtbs, err := p.prtbIndex.ByIndex(indexerName, oldPrincipalID)
	if err != nil {
		logrus.Errorf("failed to find prtb by user principal, err: %s", err.Error())
	}
	for _, prtbObj := range prtbs {
		prtb := prtbObj.(*v3.ProjectRoleTemplateBinding)
		newPrtb := prtb.DeepCopy()
		newPrtb.UserPrincipalName = newPrincipalID
		_, err := p.PRTBs.Update(newPrtb)
		if err != nil {
			logrus.Errorf("failed to update prtb %s/%s for new user principal id %s, err: %s", prtb.Namespace, prtb.Name, newPrincipalID, err.Error())
		}
	}
	crtbs, err := p.crtbIndex.ByIndex(indexerName, oldPrincipalID)
	if err != nil {
		logrus.Errorf("failed to find crtb by user principal, err: %s", err.Error())
	}
	for _, crtbObj := range crtbs {
		crtb := crtbObj.(*v3.ClusterRoleTemplateBinding)
		newCrtb := crtb.DeepCopy()
		newCrtb.UserPrincipalName = newPrincipalID
		_, err := p.CRTBs.Update(newCrtb)
		if err != nil {
			logrus.Errorf("failed to update crtb %s/%s for new user principal id %s, err: %s", crtb.Namespace, crtb.Name, newPrincipalID, err.Error())
		}
	}
	return updated, nil
}

func crtbByPrincipal(obj interface{}) ([]string, error) {
	crtb, ok := obj.(*v3.ClusterRoleTemplateBinding)
	if !ok {
		return []string{}, nil
	}
	if !strings.HasPrefix(crtb.UserPrincipalName, "sso://") {
		return []string{}, nil
	}
	return []string{crtb.UserPrincipalName}, nil
}

func prtbByPrincipal(obj interface{}) ([]string, error) {
	prtb, ok := obj.(*v3.ProjectRoleTemplateBinding)
	if !ok {
		return []string{}, nil
	}
	if !strings.HasPrefix(prtb.UserPrincipalName, "sso://") {
		return []string{}, nil
	}
	return []string{prtb.UserPrincipalName}, nil
}
