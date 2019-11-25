package workload

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	extension "k8s.io/api/extensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	SAICWorkloadIngressAnnotation = "field.pandaria.io/ingress"
	SAICWorkloadPortAnnotation    = "field.saic.pandaria.io/ports"
)

func (c *Controller) ingressExistsForWorkload(workload *Workload) (*extension.Ingress, error) {
	ingressName := workload.Name
	if strings.EqualFold(workload.Kind, "StatefulSet") {
		ingressName = fmt.Sprintf("%s-ss", workload.Name)
	}
	i, err := c.ingressLister.Get(workload.Namespace, fmt.Sprintf("%s-ingress", ingressName))
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	if i.DeletionTimestamp != nil {
		return nil, nil
	}

	return i, nil
}

func (c *Controller) CreateIngressForWorkload(workload *Workload) error {
	i, err := c.ingressExistsForWorkload(workload)
	if err != nil {
		return err
	}

	if val, ok := workload.TemplateSpec.Annotations[SAICWorkloadIngressAnnotation]; ok {
		ingressRule, err := generateIngressRule(workload, val)
		if err != nil {
			return err
		}

		if ingressRule != nil && len(ingressRule) > 0 {
			if i == nil {
				// create new ingress
				return c.createIngress(workload, ingressRule)
			}
			// update ingress
			uIngress := i.DeepCopy()
			if !reflect.DeepEqual(uIngress.Spec.Rules, ingressRule) {
				uIngress.Spec.Rules = ingressRule
				_, err = c.ingresses.Update(uIngress)
				return err
			}
		}
		return nil
	}

	// remove ingress
	if i != nil && c.isIngressOwnedByWorkload(workload, i) {
		logrus.Infof("Deleting ingress [%s/%s] for workload [%s/%s]", i.Namespace, i.Name, i.Namespace, workload.Name)
		return c.ingresses.DeleteNamespaced(i.Namespace, i.Name, &metav1.DeleteOptions{})
	}

	return nil
}

func generateIngressRule(workload *Workload, host string) ([]extension.IngressRule, error) {
	portAnnotation, ok := workload.Annotations[SAICWorkloadPortAnnotation]
	if !ok {
		return nil, nil
	}
	var portList []ContainerPort
	err := json.Unmarshal([]byte(portAnnotation), &portList)
	if err != nil {
		return nil, err
	}

	ingressRule := []extension.IngressRule{}
	for _, p := range portList {
		if p.Kind == "Http" {
			// generate ingress rule
			serviceName := workload.Name
			if p.ContainerPort != 80 {
				serviceName = fmt.Sprintf("%s%s", serviceName, strconv.Itoa(int(p.ContainerPort)))
			}
			rule := extension.IngressRule{
				Host: fmt.Sprintf("%s.%s.%s", serviceName, workload.Namespace, host),
				IngressRuleValue: extension.IngressRuleValue{
					HTTP: &extension.HTTPIngressRuleValue{
						Paths: []extension.HTTPIngressPath{
							{
								Backend: extension.IngressBackend{
									ServiceName: workload.Name,
									ServicePort: intstr.IntOrString{
										Type:   intstr.Int,
										IntVal: p.ContainerPort,
									},
								},
							},
						},
					},
				},
			}
			ingressRule = append(ingressRule, rule)
		}
	}

	return ingressRule, nil
}

func (c *Controller) createIngress(workload *Workload, ingressRule []extension.IngressRule) error {
	controller := true
	ownerRef := metav1.OwnerReference{
		Name:       workload.Name,
		APIVersion: workload.APIVersion,
		UID:        workload.UUID,
		Kind:       workload.Kind,
		Controller: &controller,
	}

	ingressAnnocations := map[string]string{}
	workloadAnnotationValue, err := IDAnnotationToString(workload.Key)
	if err != nil {
		return err
	}
	ingressAnnocations[WorkloadAnnotation] = workloadAnnotationValue
	ingressAnnocations[WorkloadAnnotatioNoop] = "true"
	ingressAnnocations[WorkloaAnnotationdPortBasedService] = "true"

	ingressName := workload.Name
	if strings.EqualFold(strings.ToLower(workload.Kind), "statefulset") {
		ingressName = fmt.Sprintf("%s-ss", workload.Name)
	}
	ingress := &extension.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{ownerRef},
			Namespace:       workload.Namespace,
			Name:            fmt.Sprintf("%s-ingress", ingressName),
			Annotations:     ingressAnnocations,
		},
		Spec: extension.IngressSpec{
			Rules: ingressRule,
		},
	}
	_, err = c.ingresses.Create(ingress)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

func (c *Controller) isIngressOwnedByWorkload(workload *Workload, ingress *extension.Ingress) bool {
	if _, ok := ingress.Annotations[WorkloaAnnotationdPortBasedService]; ok {
		for _, o := range ingress.OwnerReferences {
			if o.UID == workload.UUID {
				return true
			}
		}
	}

	return false
}
