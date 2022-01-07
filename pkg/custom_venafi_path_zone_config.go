package pki

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (

	// To be removed- left to compile
	venafiRolePolicyMapStorage  = "venafi-role-policy-map"
	venafiPolicyPath            = "venafi-policy/"
	defaultVenafiPolicyName     = "default"
	policyFieldEnforcementRoles = "enforcement_roles"
	policyFieldDefaultsRoles    = "defaults_roles"
	policyFieldImportRoles      = "import_roles"
	policyFieldCreateRole       = "create_role"
	venafiRolePolicyMapPath     = "show-venafi-role-policy-map"
	errPolicyMapDoesNotExists   = "policy map does not exists"

	// new path
	venafiZoneConfigPath  = "venafi-zone-config/"
	defaultVenafiZoneName = "default"
)

func pathVenafiZoneConfig(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiZoneConfigPath + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the Venafi zone config",
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
			"zone": {
				Type: framework.TypeString,
				Description: `Name of Venafi Platform or Cloud policy. 
Example for Platform: testPolicy\\vault
Example for Venafi Cloud: Default`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUpdateVenafiPolicy,
				Summary:  "Configure the settings of a Venafi policy",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadVenafiPolicy,
				Summary:  "Return the Venafi policy specified in path",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteVenafiPolicy,
				Summary:  "Removes the Venafi policy specified in path",
			},
		},

		HelpSynopsis:    pathVenafiZoneSyn,
		HelpDescription: pathVenafiZoneDesc,
	}
	return ret
}

func pathVenafiPolicyContent(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiZoneConfigPath + framework.GenericNameRegex("name") + "/policy",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the Venafi policy config",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadVenafiPolicyContent,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUpdateVenafiPolicyContent,
			},
		},

		HelpSynopsis:    pathVenafiZoneSyn,
		HelpDescription: pathVenafiZoneDesc,
	}
	return ret
}

func pathVenafiPolicyList(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiZoneConfigPath,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathListVenafiPolicy,
			},
		},

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
	}
	return ret
}

func (b *backend) refreshVenafiPolicyEnforcementContent(storage logical.Storage, policyName string) (err error) {

	ctx := context.Background()

	venafiPolicyConfig, err := b.getVenafiZoneConfig(ctx, &storage, policyName)
	if err != nil {
		return fmt.Errorf("error getting policy config %s: %s", policyName, err)

	}
	if venafiPolicyConfig == nil {
		return fmt.Errorf("policy config for %s is empty", policyName)
	}

	if venafiPolicyConfig.AutoRefreshInterval > 0 {
		log.Printf("%s Auto refresh enabled for policy %s. Getting policy from Venafi", logPrefixVenafiPolicyEnforcement, policyName)
	} else {
		return nil
	}

	policy, err := b.getZoneFromVenafi1(ctx, &storage, policyName)
	if err != nil {
		return fmt.Errorf("error getting policy %s from Venafi: %s", policyName, err)

	}

	log.Printf("%s Saving zone %s", logPrefixVenafiPolicyEnforcement, policyName)
	_, err = saveZoneEntry(policy, policyName, ctx, &storage)
	if err != nil {
		return fmt.Errorf("%s Error saving zone: %s", logPrefixVenafiPolicyEnforcement, err)

	}
	//policy config's credentials may be got updated so get it from storage again before saving it.
	venafiPolicyConfig, _ = b.getVenafiZoneConfig(ctx, &storage, policyName)

	jsonEntry, err := logical.StorageEntryJSON(venafiZoneConfigPath+policyName, venafiPolicyConfig)
	if err != nil {
		return fmt.Errorf("%s Error converting policy config into JSON: %s", logPrefixVenafiPolicyEnforcement, err)

	}
	if err := storage.Put(ctx, jsonEntry); err != nil {
		return fmt.Errorf("error saving policy last update time: %s", err)

	}

	return nil
}

func (b *backend) pathReadVenafiPolicyContent(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	log.Printf("%s Trying to read policy for config %s", logPrefixVenafiPolicyEnforcement, name)

	if len(name) == 0 {
		return logical.ErrorResponse("Non config specified or wrong config path name"), nil
	}

	entry, err := req.Storage.Get(ctx, venafiZoneConfigPath+name+"/policy")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("policy data is nil. Looks like it doesn't exists."), nil
	}

	var zone venafiZoneEntry
	if err := entry.DecodeJSON(&zone); err != nil {
		log.Printf("%s error reading Venafi policy configuration: %s", logPrefixVenafiPolicyEnforcement, err)
		return nil, err
	}

	//Send Zone to the user output
	respData := formZoneRespData(zone)

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) pathUpdateVenafiPolicyContent(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	policy, err := b.getZoneFromVenafi1(ctx, &req.Storage, name)
	if err != nil {
		return nil, err
	}

	policyEntry, err := saveZoneEntry(policy, name, ctx, &req.Storage)
	if err != nil {
		return nil, err
	}

	respData := formZoneRespData(*policyEntry)
	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) pathUpdateVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, err error) {
	name := data.Get("name").(string)

	log.Printf("%s Write policy endpoint configuration into storage", logPrefixVenafiPolicyEnforcement)

	venafiPolicyConfig := &venafiZoneConfigEntry{
		AutoRefreshInterval:    int64(data.Get("auto_refresh_interval").(int)),
		VenafiImportTimeout:    data.Get("import_timeout").(int),
		VenafiImportWorkers:    data.Get("import_workers").(int),
		VenafiSecret:           data.Get("venafi_secret").(string),
		Zone:                   data.Get("zone").(string),
		ImportOnlyNonCompliant: data.Get("import_only_non_compliant").(bool),
	}
	unparsedKeyUsage := data.Get("ext_key_usage").([]string)
	venafiPolicyConfig.ExtKeyUsage, err = parseExtKeyUsageParameter(unparsedKeyUsage)
	if err != nil {
		return
	}

	jsonEntry, err := logical.StorageEntryJSON(venafiZoneConfigPath+name, venafiPolicyConfig)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	log.Printf("%s Geting policy using Venafi secret: %s", logPrefixVenafiPolicyEnforcement, venafiPolicyConfig.VenafiSecret)
	policy, err := b.getZoneFromVenafi1(ctx, &req.Storage, name)
	if err != nil {
		return nil, err
	}
	policyEntry, err := saveZoneEntry(policy, name, ctx, &req.Storage)
	if err != nil {
		return nil, err
	}

	log.Printf("%s Updating roles policy attributes", logPrefixVenafiPolicyEnforcement)

	//Send policy to the user output
	respData := formZoneRespData(*policyEntry)

	return &logical.Response{
		Data:     respData,
		Warnings: []string{},
	}, nil

}

func saveZoneEntry(policy *endpoint.Policy, name string, ctx context.Context, storage *logical.Storage) (zoneEntry *venafiZoneEntry, err error) {

	//Form policy entry for storage
	zoneEntry = &venafiZoneEntry{
		SubjectCNRegexes:         policy.SubjectCNRegexes,
		SubjectORegexes:          policy.SubjectORegexes,
		SubjectOURegexes:         policy.SubjectOURegexes,
		SubjectSTRegexes:         policy.SubjectSTRegexes,
		SubjectLRegexes:          policy.SubjectLRegexes,
		SubjectCRegexes:          policy.SubjectCRegexes,
		AllowedKeyConfigurations: policy.AllowedKeyConfigurations,
		DnsSanRegExs:             policy.DnsSanRegExs,
		IpSanRegExs:              policy.IpSanRegExs,
		EmailSanRegExs:           policy.EmailSanRegExs,
		UriSanRegExs:             policy.UriSanRegExs,
		UpnSanRegExs:             policy.UpnSanRegExs,
		AllowWildcards:           policy.AllowWildcards,
		AllowKeyReuse:            policy.AllowKeyReuse,
	}

	log.Printf("%s Saving policy into Vault storage", logPrefixVenafiPolicyEnforcement)
	jsonEntry, err := logical.StorageEntryJSON(venafiZoneConfigPath+name+"/policy", zoneEntry)
	if err != nil {
		return nil, err
	}
	if err := (*storage).Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	return zoneEntry, nil
}

func formZoneRespData(zone venafiZoneEntry) (respData map[string]interface{}) {
	type printKeyConfig struct {
		KeyType   string
		KeySizes  []int    `json:",omitempty"`
		KeyCurves []string `json:",omitempty"`
	}
	keyConfigs := make([]string, len(zone.AllowedKeyConfigurations))
	for i, akc := range zone.AllowedKeyConfigurations {
		kc := printKeyConfig{akc.KeyType.String(), akc.KeySizes, nil}
		if akc.KeyType == certificate.KeyTypeECDSA {
			kc.KeyCurves = make([]string, len(akc.KeyCurves))
			for i, c := range akc.KeyCurves {
				kc.KeyCurves[i] = c.String()
			}
		}
		kb, _ := json.Marshal(kc)
		keyConfigs[i] = string(kb)
	}
	return map[string]interface{}{
		"subject_cn_regexes":         zone.SubjectCNRegexes,
		"subject_o_regexes":          zone.SubjectORegexes,
		"subject_ou_regexes":         zone.SubjectOURegexes,
		"subject_st_regexes":         zone.SubjectSTRegexes,
		"subject_l_regexes":          zone.SubjectLRegexes,
		"subject_c_regexes":          zone.SubjectCRegexes,
		"allowed_key_configurations": keyConfigs,
		"dns_san_regexes":            zone.DnsSanRegExs,
		"ip_san_regexes":             zone.IpSanRegExs,
		"email_san_regexes":          zone.EmailSanRegExs,
		"uri_san_regexes":            zone.UriSanRegExs,
		"upn_san_regexes":            zone.UpnSanRegExs,
		"allow_wildcards":            zone.AllowWildcards,
		"allow_key_reuse":            zone.AllowKeyReuse,
	}
}

func (b *backend) pathReadVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	name := data.Get("name").(string)
	log.Printf("%s Trying to read policy for config %s", logPrefixVenafiPolicyEnforcement, name)

	if len(name) == 0 {
		return logical.ErrorResponse("No config specified or wrong config path name"), nil
	}

	entry, err := req.Storage.Get(ctx, venafiZoneConfigPath+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return logical.ErrorResponse("policy config is nil. Looks like it doesn't exists."), nil
	}

	var config venafiZoneConfigEntry

	if err := entry.DecodeJSON(&config); err != nil {
		log.Printf("%s error reading Venafi policy configuration: %s", logPrefixVenafiPolicyEnforcement, err)
		return nil, err
	}

	//Send config to the user output
	respData := map[string]interface{}{
		"venafi_secret":             config.VenafiSecret,
		"zone":                      config.Zone,
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

func (b *backend) pathDeleteVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	name := data.Get("name").(string)
	rawEntry, err := req.Storage.List(ctx, venafiZoneConfigPath+name+"/")
	if err != nil {
		return nil, err
	}
	//Deleting all content of the policy
	for _, e := range rawEntry {
		err = req.Storage.Delete(ctx, venafiZoneConfigPath+name+"/"+e)
		if err != nil {
			return nil, err
		}
	}

	//Deleting policy path
	err = req.Storage.Delete(ctx, venafiZoneConfigPath+name)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathListVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	policies, err := req.Storage.List(ctx, venafiZoneConfigPath)
	var entries []string
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		//Removing from policy list repeated policy name with / at the end
		if !strings.Contains(policy, "/") {
			entries = append(entries, policy)
		}

	}
	return logical.ListResponse(entries), nil
}

func (b *backend) getVenafiZoneConfig(ctx context.Context, s *logical.Storage, n string) (*venafiZoneConfigEntry, error) {
	entry, err := (*s).Get(ctx, venafiZoneConfigPath+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result venafiZoneConfigEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

type venafiZoneConfigEntry struct {
	ExtKeyUsage            []x509.ExtKeyUsage `json:"ext_key_usage"`
	AutoRefreshInterval    int64              `json:"auto_refresh_interval"`
	LastPolicyUpdateTime   int64              `json:"last_policy_update_time"`
	VenafiImportTimeout    int                `json:"import_timeout"`
	VenafiImportWorkers    int                `json:"import_workers"`
	VenafiSecret           string             `json:"venafi_secret"`
	Zone                   string             `json:"zone"`
	ImportOnlyNonCompliant bool               `json:"import_only_non_compliant"`
}

const pathVenafiZoneSyn = `help here`
const pathVenafiZoneDesc = `description here`
