package pki

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"github.com/Venafi/vcert/v4/pkg/certificate"
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
				Callback: b.pathUpdateVenafiZoneConfig,
				Summary:  "Configure the settings of a Venafi policy",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadVenafiZoneConfig,
				Summary:  "Return the Venafi zone config specified in path",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteVenafiZoneConfig,
				Summary:  "Removes the Venafi policy specified in path",
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
				Callback: b.pathListVenafiZoneConfig,
			},
		},

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
	}
	return ret
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

	var zone zoneEntry
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

func (b *backend) pathUpdateVenafiZoneConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, err error) {
	name := data.Get("name").(string)

	log.Printf("%s Write policy endpoint configuration into storage", logPrefixVenafiPolicyEnforcement)

	config := &zoneConfigEntry{
		AutoRefreshInterval:    int64(data.Get("auto_refresh_interval").(int)),
		VenafiImportTimeout:    data.Get("import_timeout").(int),
		VenafiImportWorkers:    data.Get("import_workers").(int),
		VenafiSecret:           data.Get("venafi_secret").(string),
		Zone:                   data.Get("zone").(string),
		ImportOnlyNonCompliant: data.Get("import_only_non_compliant").(bool),
	}
	unparsedKeyUsage := data.Get("ext_key_usage").([]string)
	config.ExtKeyUsage, err = parseExtKeyUsageParameter(unparsedKeyUsage)
	if err != nil {
		return
	}

	jsonEntry, err := logical.StorageEntryJSON(venafiZoneConfigPath+name, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
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
		Data:     respData,
		Warnings: []string{},
	}, nil
}

func (b *backend) pathReadVenafiZoneConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
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

	var config zoneConfigEntry

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

func (b *backend) pathDeleteVenafiZoneConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

func (b *backend) pathListVenafiZoneConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	zoneconfigs, err := req.Storage.List(ctx, venafiZoneConfigPath)
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

func (b *backend) getVenafiZoneConfig(ctx context.Context, s *logical.Storage, configname string) (*zoneConfigEntry, error) {
	entry, err := (*s).Get(ctx, venafiZoneConfigPath+configname)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result zoneConfigEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func formZoneRespData(zone zoneEntry) (respData map[string]interface{}) {
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

const pathVenafiZoneSyn = `help here`
const pathVenafiZoneDesc = `description here`
