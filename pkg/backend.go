package pkie

import (
	"context"
	"fmt"

	pki "github.com/hashicorp/vault/builtin/logical/pki"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory creates a new backend implementing the logical.Backend interface
func FactoryV2(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {

	// standard Hashicorp Backend
	b := pki.Backend(conf)

	//update the standard pki backend with the alternative

	for _, path := range b.Backend.Paths {

		// match on the roles
		// we need to replace the "create"
		// everything else should operate as is
		if path.Pattern == "roles/"+framework.GenericNameRegex("name") {

			// update the callbacks or just rebuild?
			fmt.Println(path.Pattern)
			path.Callbacks = map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   pkiepath.pathRoleRead,
				logical.UpdateOperation: pkiepath.pathRoleCreate,
				logical.DeleteOperation: pkiepath.pathRoleDelete,
			}

		}

	}

	// now before we
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}
