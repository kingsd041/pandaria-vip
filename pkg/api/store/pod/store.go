package pod

import (
	"github.com/rancher/norman/store/transform"
	"github.com/rancher/norman/types"
	"github.com/rancher/rancher/pkg/clustermanager"
	"github.com/rancher/rancher/pkg/ref"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"k8s.io/client-go/tools/cache"

	// pandaria
	"github.com/rancher/rancher/pkg/api/customization/pod"
	"github.com/rancher/types/user"
)

const (
	nodeNameIdx = "nodeNameId"
)

func New(store types.Store, clusterManager *clustermanager.Manager, scaledContext *config.ScaledContext) types.Store {
	return &transform.Store{
		Store:       store,
		Transformer: newPT(clusterManager, scaledContext),
	}
}

func newPT(clusterManager *clustermanager.Manager, scaledContext *config.ScaledContext) transform.TransformerFunc {
	scaledContext.Management.Nodes("").Controller().Informer().AddIndexers(cache.Indexers{
		nodeNameIdx: func(obj interface{}) ([]string, error) {
			node := obj.(*v3.Node)
			name := node.Status.NodeName
			if name == "" {
				return nil, nil
			}
			return []string{ref.FromStrings(node.Namespace, name)}, nil
		},
	})

	pt := &podTransformer{
		clusterManager: clusterManager,
		nodeIndexer:    scaledContext.Management.Nodes("").Controller().Informer().GetIndexer(),
		userManager:    scaledContext.UserManager,
	}
	return pt.transformer
}

type podTransformer struct {
	clusterManager *clustermanager.Manager
	nodeIndexer    cache.Indexer
	userManager    user.Manager
}

func (p *podTransformer) transformer(context *types.APIContext, schema *types.Schema, data map[string]interface{}, opt *types.QueryOptions) (map[string]interface{}, error) {
	if data == nil {
		return data, nil
	}
	owner := resolveWorkloadID(context, data)
	if owner != "" {
		data["workloadId"] = owner
	}

	clusterName := p.clusterManager.ClusterName(context)
	nodeName, _ := data["nodeId"].(string)
	nodes, err := p.nodeIndexer.ByIndex(nodeNameIdx, ref.FromStrings(clusterName, nodeName))
	if err != nil {
		return nil, err
	}

	if len(nodes) == 1 {
		node := nodes[0].(*v3.Node)
		data["nodeId"] = ref.FromStrings(node.Namespace, node.Name)
	}

	actionWrapper := pod.ActionWrapper{
		UserManager:    p.userManager,
		ClusterManager: p.clusterManager,
	}
	schema.Formatter = pod.Formatter
	schema.ActionHandler = actionWrapper.ActionHandler
	return data, nil
}
