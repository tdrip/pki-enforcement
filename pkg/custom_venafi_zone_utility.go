package pki

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) getZoneFromVenafi(ctx context.Context, storage *logical.Storage, zone string, role string) (policy *endpoint.Policy, err error) {
	log.Printf("%s Creating Venafi client", logPrefixEnforcement)

	cl, err := b.RoleBasedClientVenafi(ctx, storage, role)
	if err != nil {
		return
	}
	log.Printf("%s Getting policy from Venafi endpoint", logPrefixEnforcement)

	policy, err = cl.ReadPolicyConfiguration()
	if (err != nil) && (cl.GetType() == endpoint.ConnectorTypeTPP) {
		msg := err.Error()

		//catch the scenario when token is expired and deleted.
		var regex = regexp.MustCompile("(expired|invalid)_token")

		//validate if the error is related to a expired access token, at this moment the only way can validate this is using the error message
		//and verify if that message describes errors related to expired access token.
		code := getStatusCode(msg)
		if code == HTTP_UNAUTHORIZED && regex.MatchString(msg) {

			cfg, err := b.getRoleBasedConfig(ctx, storage, role)

			if err != nil {
				return nil, err
			}

			if cfg.Credentials.RefreshToken != "" {
				err = synchronizedUpdateAccessToken(cfg, b, ctx, storage, zone)

				if err != nil {
					return nil, err
				}

				//everything went fine so get the new client with the new refreshed access token
				cl, err := b.RoleBasedClientVenafi(ctx, storage, role)
				if err != nil {
					return nil, err
				}

				b.Logger().Debug("Making certificate request again")

				policy, err = cl.ReadPolicyConfiguration()
				if err != nil {
					return nil, err
				} else {
					return policy, nil
				}
			} else {
				err = fmt.Errorf("tried to get new access token but refresh token is empty")
				return nil, err
			}

		} else {
			return nil, err
		}
	}
	if policy == nil {
		err = fmt.Errorf("expected policy but got nil from Venafi endpoint %v", policy)
		return
	}

	return
}

func (b *backend) updateRoleEntryFromVenafi(ctx context.Context, storage logical.Storage, role *roleEntry) (zoneentry *roleEntry, err error) {

	// grab the zone from Venafi
	zone, err := b.getZoneFromVenafi(ctx, &storage, "", role.Name)
	if err != nil {
		return nil, err
	}

	// Venafi have this concept of zone/policy which is interchangeable
	// Vault has policy
	// we shall stick to zone so that it is clear
	// this is a venafi zone (path in a venafi platform)

	role.SubjectCNRegexes = zone.SubjectCNRegexes
	role.SubjectORegexes = zone.SubjectORegexes
	role.SubjectOURegexes = zone.SubjectOURegexes
	role.SubjectSTRegexes = zone.SubjectSTRegexes
	role.SubjectLRegexes = zone.SubjectLRegexes
	role.SubjectCRegexes = zone.SubjectCRegexes
	role.AllowedKeyConfigurations = zone.AllowedKeyConfigurations
	role.DnsSanRegExs = zone.DnsSanRegExs
	role.IpSanRegExs = zone.IpSanRegExs
	role.EmailSanRegExs = zone.EmailSanRegExs
	role.UriSanRegExs = zone.UriSanRegExs
	role.UpnSanRegExs = zone.UpnSanRegExs
	role.AllowWildcards = zone.AllowWildcards
	role.AllowKeyReuse = zone.AllowKeyReuse

	return role, nil
}
