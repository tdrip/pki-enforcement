package pki

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// new path
	enforcementConfigPath  = "enforcement-config/"
	defaultEnforcementName = "default"

	logPrefixEnforcementConfig = "ENFORCEMENT CONFIG: "
)

type enforcementConfigEntry struct {

	// This is zone refresh configuration
	AutoRefreshInterval  int64 `json:"auto_refresh_interval"`
	LastPolicyUpdateTime int64 `json:"last_policy_update_time"`

	// This is configuration for the Venafi Import tasks
	VenafiImportTimeout    int  `json:"import_timeout"`
	VenafiImportWorkers    int  `json:"import_workers"`
	ImportOnlyNonCompliant bool `json:"import_only_non_compliant"`

	// This is for vcert client configuration (Secret)
	VenafiSecret string `json:"venafi_secret"`

	// this is the path for import and enforcement
	ParentZone string `json:"parent_zone"`

	// These are for enforcement
	ExtKeyUsage []x509.ExtKeyUsage `json:"ext_key_usage"`
}

func pathEnforcementConfig(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: enforcementConfigPath + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the Enforcement config",
			},
			"ext_key_usage": {
				Type:    framework.TypeCommaStringSlice,
				Default: []string{},
				Description: `A comma-separated string or list of allowed extended key usages. Valid values can be found at
https://golang.org/pkg/crypto/x509/#ExtKeyUsage
-- simply drop the "ExtKeyUsage" part of the name.
Also you can use constants from this module (like 1, 5,8) direct or use OIDs (like 1.3.6.1.5.5.7.3.4)`,
			},
			"auto_refresh_interval": {
				Type:        framework.TypeInt,
				Default:     0,
				Description: `Interval of policy update from Venafi in seconds. Set it to 0 to disable automatic policy update`,
			},
			"import_timeout": {
				Type:        framework.TypeInt,
				Default:     15,
				Description: `Timeout in second to rerun import queue`,
			},
			"import_workers": {
				Type:        framework.TypeInt,
				Default:     5,
				Description: `Max amount of simultaneously working instances of vcert import`,
			},
			"import_only_non_compliant": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Only import certificates into Venafi that do not comply with zone policy",
			},
			"venafi_secret": {
				Type:        framework.TypeString,
				Description: `The name of the credentials object to be used for authentication`,
				Required:    true,
			},
			"parent_zone": {
				Type: framework.TypeString,
				Description: `Name of Venafi Platform or Cloud policy. 
Example for Platform: testPolicy\\vault
Example for Venafi Cloud: Default`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUpdateEnforcementConfig,
				Summary:  "Configure the settings of a enforcement",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadEnforcementConfig,
				Summary:  "Return the enforcement config specified in path",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteEnforcementConfig,
				Summary:  "Removes the enforcement specified in path",
			},
		},

		HelpSynopsis:    pathEnforcementSyn,
		HelpDescription: pathEnforcementDesc,
	}
	return ret
}

func pathVenafiPolicyList(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: enforcementConfigPath,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathListEnforcementConfig,
			},
		},

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
	}
	return ret
}

func (b *backend) pathUpdateEnforcementConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, err error) {
	name := data.Get("name").(string)

	log.Printf("%s Write policy endpoint configuration into storage", logPrefixEnforcementConfig)

	config := &enforcementConfigEntry{
		AutoRefreshInterval:    int64(data.Get("auto_refresh_interval").(int)),
		VenafiImportTimeout:    data.Get("import_timeout").(int),
		VenafiImportWorkers:    data.Get("import_workers").(int),
		VenafiSecret:           data.Get("venafi_secret").(string),
		ParentZone:             data.Get("parent_zone").(string),
		ImportOnlyNonCompliant: data.Get("import_only_non_compliant").(bool),
	}
	unparsedKeyUsage := data.Get("ext_key_usage").([]string)
	config.ExtKeyUsage, err = parseExtKeyUsageParameter(unparsedKeyUsage)
	if err != nil {
		return
	}

	jsonEntry, err := logical.StorageEntryJSON(enforcementConfigPath+name, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}
	//Send config to the user output
	respData := map[string]interface{}{
		"venafi_secret":             config.VenafiSecret,
		"parent_zone":               config.ParentZone,
		"auto_refresh_interval":     config.AutoRefreshInterval,
		"last_policy_update_time":   config.LastPolicyUpdateTime,
		"import_timeout":            config.VenafiImportTimeout,
		"import_workers":            config.VenafiImportWorkers,
		"import_only_non_compliant": config.ImportOnlyNonCompliant,
	}

	return &logical.Response{
		Data:     respData,
		Warnings: []string{},
	}, nil
}

func (b *backend) pathReadEnforcementConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	name := data.Get("name").(string)
	log.Printf("%s Trying to read policy for config %s", logPrefixEnforcementConfig, name)

	if len(name) == 0 {
		return logical.ErrorResponse("No config specified or wrong config path name"), nil
	}

	entry, err := req.Storage.Get(ctx, enforcementConfigPath+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return logical.ErrorResponse("policy config is nil. Looks like it doesn't exists."), nil
	}

	var config enforcementConfigEntry

	if err := entry.DecodeJSON(&config); err != nil {
		log.Printf("%s error reading Venafi policy configuration: %s", logPrefixEnforcementConfig, err)
		return nil, err
	}

	//Send config to the user output
	respData := map[string]interface{}{
		"venafi_secret":             config.VenafiSecret,
		"parent_zone":               config.ParentZone,
		"auto_refresh_interval":     config.AutoRefreshInterval,
		"last_policy_update_time":   config.LastPolicyUpdateTime,
		"import_timeout":            config.VenafiImportTimeout,
		"import_workers":            config.VenafiImportWorkers,
		"import_only_non_compliant": config.ImportOnlyNonCompliant,
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) pathDeleteEnforcementConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	name := data.Get("name").(string)
	rawEntry, err := req.Storage.List(ctx, enforcementConfigPath+name+"/")
	if err != nil {
		return nil, err
	}
	//Deleting all content of the policy
	for _, e := range rawEntry {
		err = req.Storage.Delete(ctx, enforcementConfigPath+name+"/"+e)
		if err != nil {
			return nil, err
		}
	}

	//Deleting policy path
	err = req.Storage.Delete(ctx, enforcementConfigPath+name)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathListEnforcementConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	zoneconfigs, err := req.Storage.List(ctx, enforcementConfigPath)
	var entries []string
	if err != nil {
		return nil, err
	}
	for _, zoneconfig := range zoneconfigs {
		//Removing from policy list repeated policy name with / at the end
		if !strings.Contains(zoneconfig, "/") {
			entries = append(entries, zoneconfig)
		}

	}
	return logical.ListResponse(entries), nil
}

func (b *backend) getEnforcementConfig(ctx context.Context, s *logical.Storage, configname string) (*enforcementConfigEntry, error) {
	entry, err := (*s).Get(ctx, enforcementConfigPath+configname)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result enforcementConfigEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (b *backend) getConfigWithSecret(ctx context.Context, s *logical.Storage, configname string) (*enforcementConfigEntry, error) {

	// configname was empty so we switch to the default
	// this will allow us to have a default config and not store the word default on all roles
	if len(configname) == 0 {
		configname = defaultEnforcementName
	}

	config, err := b.getEnforcementConfig(ctx, s, configname)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("expected config but got nil from Vault storage %v", config)
	}
	if config.VenafiSecret == "" {
		return nil, fmt.Errorf("empty Venafi secret name")
	}

	return config, nil
}

const pathEnforcementSyn = `help here`
const pathEnforcementDesc = `description here`
