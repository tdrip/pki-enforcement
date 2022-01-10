package pki

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) RoleBasedClientVenafi(ctx context.Context, s *logical.Storage, configname string, roleName string) (endpoint.Connector, string, error) {

	secret, zone, err := b.getconfig(ctx, s, configname, roleName)
	if err != nil {
		return nil, zone, err
	}

	connector, err := secret.getConnection(zone)
	return connector, zone, err
}

func (b *backend) getconfig(ctx context.Context, s *logical.Storage, configname string, roleName string) (*venafiSecretEntry, string, error) {

	if len(roleName) == 0 {
		return nil, "", fmt.Errorf("Lookup of zone failed as role name is missing")
	}

	config, err := b.getConfigWithSecret(ctx, s, configname)
	if err != nil {
		return nil, "", err
	}

	secret, err := b.getVenafiSecret(ctx, s, config.VenafiSecret)
	if err != nil {
		return nil, "", err
	}
	if secret == nil {
		return nil, "", fmt.Errorf("expected Venafi secret but got nil from Vault storage %v", secret)
	}

	// We will use the zone of the client and add the role name to this zone to get the details
	// this makes for a simpler implementation

	zone := ""

	if config.ParentZone != "" {
		b.Logger().Debug("Using zone from Venafi Config.", "zone", config.ParentZone)
		zone = config.ParentZone + "\\" + roleName
	} else {
		b.Logger().Debug("Using zone from Venafi secret since Policy zone not found.", "zone", secret.Zone)
		zone = secret.Zone + "\\" + roleName
	}

	return secret, zone, nil
}

func (b *backend) getRoleBasedConfig(ctx context.Context, s *logical.Storage, configname string, roleName string) (*vcert.Config, error) {
	secret, zone, err := b.getconfig(ctx, s, configname, roleName)
	if err != nil {
		return nil, err
	}
	return secret.getVCertConfig(zone, true)
}

func pp(a interface{}) string {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return fmt.Sprint(string(b))
}

type venafiSecretEntry struct {
	TPPUrl          string `json:"tpp_url"`
	URL             string `json:"url"`
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	Zone            string `json:"zone"`
	TPPPassword     string `json:"tpp_password"`
	TPPUser         string `json:"tpp_user"`
	TrustBundleFile string `json:"trust_bundle_file"`
	Apikey          string `json:"apikey"`
	CloudURL        string `json:"cloud_url"`
}

func (c venafiSecretEntry) getConnection(zone string) (endpoint.Connector, error) {
	cfg, err := c.getVCertConfig(zone, false)
	if err == nil {
		client, err := vcert.NewClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to get Venafi issuer client: %s", err)
		} else {
			return client, nil
		}

	} else {
		return nil, err
	}
}

func (c venafiSecretEntry) getVCertConfig(zone string, includeRefreshToken bool) (*vcert.Config, error) {
	if zone == "" {
		zone = c.Zone
	}

	var cfg = &vcert.Config{
		BaseUrl:     c.URL,
		Zone:        zone,
		LogVerbose:  true,
		Credentials: &endpoint.Authentication{},
	}

	if c.URL != "" && c.AccessToken != "" {
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.Credentials.AccessToken = c.AccessToken
		if includeRefreshToken {
			cfg.Credentials.RefreshToken = c.RefreshToken
		}

	} else if c.URL != "" && c.TPPUser != "" && c.TPPPassword != "" {
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.Credentials.User = c.TPPUser
		cfg.Credentials.Password = c.TPPPassword

	} else if c.Apikey != "" {
		cfg.ConnectorType = endpoint.ConnectorTypeCloud
		cfg.Credentials.APIKey = c.Apikey

	} else {
		return nil, fmt.Errorf("failed to build config for Venafi conection")
	}

	if cfg.ConnectorType == endpoint.ConnectorTypeTPP {
		if c.TrustBundleFile != "" {
			trustBundle, err := ioutil.ReadFile(c.TrustBundleFile)
			if err != nil {
				log.Printf("Can`t read trust bundle from file %s: %v\n", c.TrustBundleFile, err)
				return nil, err
			}
			cfg.ConnectionTrust = string(trustBundle)
		}
	}
	return cfg, nil
}

func (c venafiSecretEntry) getMaskString() string {
	return "********"
}
