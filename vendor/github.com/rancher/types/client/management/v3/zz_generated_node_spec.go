package client

const (
	NodeSpecType                          = "nodeSpec"
	NodeSpecFieldControlPlane             = "controlPlane"
	NodeSpecFieldCustomConfig             = "customConfig"
	NodeSpecFieldDescription              = "description"
	NodeSpecFieldDesiredNodeUnschedulable = "desiredNodeUnschedulable"
	NodeSpecFieldDisplayName              = "displayName"
	NodeSpecFieldEtcd                     = "etcd"
	NodeSpecFieldImported                 = "imported"
	NodeSpecFieldMetadataUpdate           = "metadataUpdate"
	NodeSpecFieldNodeDrainInput           = "nodeDrainInput"
	NodeSpecFieldNodePoolID               = "nodePoolId"
	NodeSpecFieldNodeTemplateID           = "nodeTemplateId"
	NodeSpecFieldPodCidr                  = "podCidr"
	NodeSpecFieldProviderId               = "providerId"
	NodeSpecFieldRequestedHostname        = "requestedHostname"
	NodeSpecFieldTaints                   = "taints"
	NodeSpecFieldUnschedulable            = "unschedulable"
	NodeSpecFieldWorker                   = "worker"
)

type NodeSpec struct {
	ControlPlane             bool            `json:"controlPlane,omitempty" yaml:"controlPlane,omitempty"`
	CustomConfig             *CustomConfig   `json:"customConfig,omitempty" yaml:"customConfig,omitempty"`
	Description              string          `json:"description,omitempty" yaml:"description,omitempty"`
	DesiredNodeUnschedulable string          `json:"desiredNodeUnschedulable,omitempty" yaml:"desiredNodeUnschedulable,omitempty"`
	DisplayName              string          `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	Etcd                     bool            `json:"etcd,omitempty" yaml:"etcd,omitempty"`
	Imported                 bool            `json:"imported,omitempty" yaml:"imported,omitempty"`
	MetadataUpdate           *MetadataUpdate `json:"metadataUpdate,omitempty" yaml:"metadataUpdate,omitempty"`
	NodeDrainInput           *NodeDrainInput `json:"nodeDrainInput,omitempty" yaml:"nodeDrainInput,omitempty"`
	NodePoolID               string          `json:"nodePoolId,omitempty" yaml:"nodePoolId,omitempty"`
	NodeTemplateID           string          `json:"nodeTemplateId,omitempty" yaml:"nodeTemplateId,omitempty"`
	PodCidr                  string          `json:"podCidr,omitempty" yaml:"podCidr,omitempty"`
	ProviderId               string          `json:"providerId,omitempty" yaml:"providerId,omitempty"`
	RequestedHostname        string          `json:"requestedHostname,omitempty" yaml:"requestedHostname,omitempty"`
	Taints                   []Taint         `json:"taints,omitempty" yaml:"taints,omitempty"`
	Unschedulable            bool            `json:"unschedulable,omitempty" yaml:"unschedulable,omitempty"`
	Worker                   bool            `json:"worker,omitempty" yaml:"worker,omitempty"`
}
