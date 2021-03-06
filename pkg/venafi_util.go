package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	HTTP_UNAUTHORIZED = 401
)

/*
func normalizeSerial(serial string) string {
	return strings.Replace(strings.ToLower(serial), ":", "-", -1)
}
*/

func parseExtKeyUsageParameter(unparsed []string) ([]x509.ExtKeyUsage, error) {
	extKeyUsages := make([]x509.ExtKeyUsage, 0, len(unparsed))
	oidRegexp := regexp.MustCompile(`(\d+\.)+\d`)
	idRegexp := regexp.MustCompile(`\d+`)
	stringRegexp := regexp.MustCompile(`[a-z]+`)
	for _, s := range unparsed {
		switch {
		case oidRegexp.MatchString(s):
			oid, _ := stringToOid(s)
			eku, ok := extKeyUsageFromOID(oid)
			if !ok {
				return nil, fmt.Errorf("unknow oid: %s", s)
			}
			extKeyUsages = append(extKeyUsages, eku)
		case idRegexp.MatchString(s):
			eku, err := ekuParse(s)
			if err != nil {
				return nil, err
			}
			extKeyUsages = append(extKeyUsages, eku)
		case stringRegexp.MatchString(s):
			eku, known := findEkuByName(s)
			if !known {
				return nil, fmt.Errorf("unknown eku: %s", s)
			}
			extKeyUsages = append(extKeyUsages, eku)
		default:
			return nil, fmt.Errorf("unknow extKeyUsage format: %s", s)
		}
	}
	return extKeyUsages, nil
}

var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

var extKeyUsageOIDs = []struct {
	extKeyUsage x509.ExtKeyUsage
	oid         asn1.ObjectIdentifier
	name        string
}{
	{x509.ExtKeyUsageAny, oidExtKeyUsageAny, "any"},
	{x509.ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth, "serverauth"},
	{x509.ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth, "clientauth"},
	{x509.ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning, "codesigning"},
	{x509.ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection, "emailprotection"},
	{x509.ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem, "ipsecendsystem"},
	{x509.ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel, "ipsectunnel"},
	{x509.ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser, "ipsecuser"},
	{x509.ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping, "timestamping"},
	{x509.ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning, "ocspsigning"},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto, "microsoftservergatedcrypto"},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto, "netscapeservergatedcrypto"},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning, "microsoftcommercialcodesigning"},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning, "microsoftkernelcodesigning"},
}

func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku x509.ExtKeyUsage, ok bool) {
	for _, triplet := range extKeyUsageOIDs {
		if oid.Equal(triplet.oid) {
			return triplet.extKeyUsage, true
		}
	}
	return
}

func checkExtKeyUsage(eku x509.ExtKeyUsage) bool {
	for _, triplet := range extKeyUsageOIDs {
		if triplet.extKeyUsage == eku {
			return true
		}
	}
	return false
}

func findEkuByName(name string) (x509.ExtKeyUsage, bool) {
	name = strings.ToLower(name)
	for _, triplet := range extKeyUsageOIDs {
		if triplet.name == name {
			return triplet.extKeyUsage, true
		}
	}
	return 0, false
}
func ekuParse(s string) (eku x509.ExtKeyUsage, err error) {
	i, _ := strconv.Atoi(s)
	eku = x509.ExtKeyUsage(i)
	if checkExtKeyUsage(eku) {
		return
	}
	err = fmt.Errorf("unknow eku: %s", s)
	return
}

func ekuInSlice(i x509.ExtKeyUsage, s []x509.ExtKeyUsage) bool {
	for _, j := range s {
		if j == i {
			return true
		}
	}
	return false
}
func compareEkuList(target, allowed []x509.ExtKeyUsage) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, i := range target {
		if !ekuInSlice(i, allowed) {
			return false
		}
	}
	return true
}

func intInSlice(i int, s []int) bool {
	for _, j := range s {
		if i == j {
			return true
		}
	}
	return false
}

func curveInSlice(i certificate.EllipticCurve, s []certificate.EllipticCurve) bool {
	for _, j := range s {
		if i == j {
			return true
		}
	}
	return false
}

func checkKey(keyType string, bitSize int, curveStr string, allowed []endpoint.AllowedKeyConfiguration) (valid bool) {
	for _, allowedKey := range allowed {
		var kt certificate.KeyType
		if err := kt.Set(keyType); err != nil {
			return false
		}
		if allowedKey.KeyType == kt {
			switch allowedKey.KeyType {
			case certificate.KeyTypeRSA:
				return intInSlice(bitSize, allowedKey.KeySizes)
			case certificate.KeyTypeECDSA:
				var curve certificate.EllipticCurve
				if err := curve.Set(curveStr); err != nil {
					return false
				}
				return curveInSlice(curve, allowedKey.KeyCurves)
			default:
				return
			}
		}
	}
	return
}

func checkStringByRegexp(s string, regexList []string) (matched bool) {
	var err error
	for _, r := range regexList {
		matched, err = regexp.MatchString(r, s)
		if err == nil && matched {
			return true
		}
	}
	return
}

func checkStringArrByRegexp(ss []string, regexList []string, optional bool) (matched bool) {
	if optional && len(ss) == 0 {
		return true
	}
	if len(ss) == 0 {
		ss = []string{""}
	}
	for _, s := range ss {
		if !checkStringByRegexp(s, regexList) {
			return false
		}
	}
	return true
}

func ecdsaCurvesSizesToName(bitLen int) string {
	return fmt.Sprintf("P%d", bitLen)
}

func getTppConnector(cfg *vcert.Config) (*tpp.Connector, error) {

	var connectionTrustBundle *x509.CertPool
	if cfg.ConnectionTrust != "" {
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(cfg.ConnectionTrust)) {
			return nil, fmt.Errorf("failed to parse PEM trust bundle")
		}
	}
	tppConnector, err := tpp.NewConnector(cfg.BaseUrl, "", cfg.LogVerbose, connectionTrustBundle)
	if err != nil {
		return nil, fmt.Errorf("could not create TPP connector: %s", err)
	}

	return tppConnector, nil
}

func synchronizedUpdateAccessToken(cfg *vcert.Config, b *backend, ctx context.Context, storage *logical.Storage, enforcementConfigName string) error {
	b.mux.Lock()
	err := updateAccessToken(cfg, b, ctx, storage, enforcementConfigName)
	b.mux.Unlock()
	return err
}

func updateAccessToken(cfg *vcert.Config, b *backend, ctx context.Context, storage *logical.Storage, enforcementConfigName string) error {
	tppConnector, _ := getTppConnector(cfg)

	httpClient, err := getHTTPClient(cfg.ConnectionTrust)
	if err != nil {
		return err
	}

	tppConnector.SetHTTPClient(httpClient)

	resp, err := tppConnector.RefreshAccessToken(&endpoint.Authentication{
		RefreshToken: cfg.Credentials.RefreshToken,
		ClientId:     "hashicorp-vault-monitor-by-venafi",
		Scope:        "certificate:discover,manage",
	})

	if err != nil {
		return err
	}

	if resp.Access_token != "" && resp.Refresh_token != "" {

		err := storeAccessData(b, ctx, storage, enforcementConfigName, resp)
		if err != nil {
			return err
		}

	}

	return nil
}

func storeAccessData(b *backend, ctx context.Context, storage *logical.Storage, enforcementConfigName string, resp tpp.OauthRefreshAccessTokenResponse) error {
	if len(enforcementConfigName) == 0 {
		enforcementConfigName = defaultEnforcementName
	}
	policy, err := b.getEnforcementConfig(ctx, storage, enforcementConfigName)

	if err != nil {
		return err
	}

	secret, err := b.getVenafiSecret(ctx, storage, policy.VenafiSecret)
	if err != nil {
		return err
	}

	secret.RefreshToken = resp.Refresh_token

	secret.AccessToken = resp.Access_token

	// Store it
	jsonEntry, err := logical.StorageEntryJSON(venafiSecretPath+policy.VenafiSecret, secret)
	if err != nil {
		return err
	}

	if err := (*storage).Put(ctx, jsonEntry); err != nil {
		return err
	}

	//save the new credential on the backend storage.
	storageB := b.storage
	if err := storageB.Put(ctx, jsonEntry); err != nil {
		return err
	}

	return nil
}

func getHTTPClient(trustBundlePem string) (*http.Client, error) {

	var netTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	tlsConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig

	if tlsConfig == nil {
		/* #nosec */
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}

	if trustBundlePem != "" {
		trustBundle, err := parseTrustBundlePEM(trustBundlePem)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = trustBundle
	}

	tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	netTransport.TLSClientConfig = tlsConfig

	client := &http.Client{
		Timeout:   time.Second * 30,
		Transport: netTransport,
	}

	return client, nil
}

func parseTrustBundlePEM(trustBundlePem string) (*x509.CertPool, error) {
	var connectionTrustBundle *x509.CertPool

	if trustBundlePem != "" {
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(trustBundlePem)) {
			return nil, fmt.Errorf("failed to parse PEM trust bundle")
		}
	} else {
		return nil, fmt.Errorf("trust bundle PEM data is empty")
	}

	return connectionTrustBundle, nil
}

func getStatusCode(msg string) int64 {

	var statusCode int64
	splittedMsg := strings.Split(msg, ":")

	for i := 0; i < len(splittedMsg); i++ {

		current := splittedMsg[i]
		current = strings.TrimSpace(current)

		if current == "Invalid status" {

			status := splittedMsg[i+1]
			status = strings.TrimSpace(status)
			splittedStatus := strings.Split(status, " ")
			statusCode, _ = strconv.ParseInt(splittedStatus[0], 10, 64)
			break

		}
	}

	return statusCode
}

func createConfigFromFieldData(data *venafiSecretEntry) (*vcert.Config, error) {
	var cfg = &vcert.Config{}

	cfg.BaseUrl = data.URL
	cfg.Zone = data.Zone
	cfg.LogVerbose = true

	trustBundlePath := data.TrustBundleFile

	if trustBundlePath != "" {

		var trustBundlePEM string
		trustBundle, err := ioutil.ReadFile(trustBundlePath)

		if err != nil {
			return cfg, err
		}

		trustBundlePEM = string(trustBundle)
		cfg.ConnectionTrust = trustBundlePEM
	}

	cfg.ConnectorType = endpoint.ConnectorTypeTPP

	cfg.Credentials = &endpoint.Authentication{

		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
	}

	return cfg, nil
}

func getAccessData(cfg *vcert.Config) (tpp.OauthRefreshAccessTokenResponse, error) {

	var tokenInfoResponse tpp.OauthRefreshAccessTokenResponse
	tppConnector, _ := getTppConnector(cfg)
	httpClient, err := getHTTPClient(cfg.ConnectionTrust)

	if err != nil {
		return tokenInfoResponse, err
	}

	tppConnector.SetHTTPClient(httpClient)

	tokenInfoResponse, err = tppConnector.RefreshAccessToken(&endpoint.Authentication{
		RefreshToken: cfg.Credentials.RefreshToken,
		ClientId:     "hashicorp-vault-monitor-by-venafi",
		Scope:        "certificate:discover,manage",
	})

	return tokenInfoResponse, err

}
