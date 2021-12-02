package pkie

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestBackend(t *testing.T) {

	defaultLeaseTTLVal := time.Hour * 24
	maxLeaseTTLVal := time.Hour * 24 * 32
	b, err := FactoryV2(context.Background(), &logical.BackendConfig{
		Logger: nil,
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
	})
	if err != nil {
		t.Fatalf("Unable to create backend: %s", err)
	}

	for _, v := range b.Paths {
		t.Log(v)
	}

}
