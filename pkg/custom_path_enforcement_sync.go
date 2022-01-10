package pki

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	hconsts "github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

const venafiSyncPolicyListPath = "enforcement-sync"
const logPrefixEnforcementSync = "VENAFI_IMPORT: "

func pathEnforcementSync(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiSyncPolicyListPath,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathReadEnforcementSync,
		},
	}
	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})
	return ret
}

func (b *backend) pathReadEnforcementSync(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	//Get role list with role sync param
	log.Println("starting to read sync roles")
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	if len(roles) == 0 {
		return nil, fmt.Errorf("No roles found in storage")
	}

	var entries []string

	for _, roleName := range roles {
		log.Println("looking role ", roleName)
		//	Read previous role parameters
		pkiRoleEntry, err := b.getPKIRoleEntry(ctx, req.Storage, roleName)
		if err != nil {
			log.Printf("%s", err)
			continue
		}

		if pkiRoleEntry == nil {
			continue
		}

		var entry []string
		entry = append(entry, fmt.Sprintf("role: %s sync zone: %s", roleName, pkiRoleEntry.Zone))
		entries = append(entries, entry...)

	}
	return logical.ListResponse(entries), nil
}

func (b *backend) syncRoleWithEnforcementRegister(conf *logical.BackendConfig) {
	log.Printf("%s registering policy sync controller", logPrefixEnforcementSync)
	b.taskStorage.register("policy-sync-controller", func() {
		err := b.syncEnforcementAndRoleDefaults(conf)
		if err != nil {
			log.Printf("%s %s", logPrefixEnforcementSync, err)
		}
	}, 1, time.Second*15)
}

func (b *backend) syncEnforcementAndRoleDefaults(conf *logical.BackendConfig) (err error) {
	replicationState := conf.System.ReplicationState()
	//Checking if we are on master or on the stanby Vault server
	isSlave := !(conf.System.LocalMount() || !replicationState.HasState(hconsts.ReplicationPerformanceSecondary)) ||
		replicationState.HasState(hconsts.ReplicationDRSecondary) ||
		replicationState.HasState(hconsts.ReplicationPerformanceStandby)
	if isSlave {
		log.Printf("%s We're on slave. Sleeping", logPrefixEnforcementSync)
		return
	}
	log.Printf("%s We're on master. Starting to synchronise policy", logPrefixEnforcementSync)

	ctx := context.Background()

	log.Printf("%s We're on master. Starting to synchronise policy", logPrefixEnforcementSync)

	defaultpolicyname := ""
	defaultPolicyConfig, err := b.getEnforcementConfig(ctx, &b.storage, defaultpolicyname)
	if err != nil {
		log.Printf("%s Error getting policy config for policy %s: %s", logPrefixEnforcementSync, defaultpolicyname, err)
	}

	if defaultPolicyConfig == nil {
		log.Printf("%s Policy config for %s is nil. Skipping", logPrefixEnforcementSync, defaultpolicyname)
	}

	log.Println("starting to read sync roles")
	roles, err := b.storage.List(ctx, "role/")
	if err != nil {
		return err
	}

	if len(roles) == 0 {
		return fmt.Errorf("No roles found in storage")
	}

	for _, roleName := range roles {

		//	Read previous role parameters
		pkiRoleEntry, err := b.getPKIRoleEntry(ctx, b.storage, roleName)
		if err != nil {
			return fmt.Errorf("%s", err)
		}

		if pkiRoleEntry == nil {
			return fmt.Errorf("PKI role %s is empty or does not exist", roleName)
		}

		log.Printf("%s check last policy updated time", logPrefixEnforcementSync)
		timePassed := time.Now().Unix() - defaultPolicyConfig.LastPolicyUpdateTime
		//update only if needed
		//TODO: Make test to check this refresh
		if (timePassed) < defaultPolicyConfig.AutoRefreshInterval {
			continue
		}

		// we don't need to synchronise defaults
		// just grab the new fields
		//pkiRoleEntry.synchronizeRoleDefaults(b, ctx, b.storage, roleName)

		// we do not have a specific zone so we can calculate it
		updatedEntry, err := b.updateRoleEntryFromVenafi(ctx, b.storage, pkiRoleEntry)
		if err != nil {
			return err
		}

		pkiRoleEntry = updatedEntry

		//set new last updated
		pkiRoleEntry.LastZoneUpdateTime = time.Now().Unix()

		err = pkiRoleEntry.store(ctx, b.storage)
		if err != nil {
			return err
		}
	}

	return err
}
