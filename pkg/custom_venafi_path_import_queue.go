package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/verror"
	"github.com/hashicorp/vault/sdk/framework"
	hconsts "github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

const logPrefixVenafiImport = "VENAFI_IMPORT: "

//Jobs tructure for import queue worker
type Job struct {
	id       int
	entry    string
	roleName string
	//policyName string
	importPath string
	ctx        context.Context
	//req        *logical.Request
	storage                *logical.Storage
	importOnlyNonCompliant bool
}

// This returns the list of queued for import to TPP certificates
func pathImportQueue(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "import-queue/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathUpdateImportQueue,
			//TODO: add delete operation to stop import queue and delete it
			//TODO: add delete operation to delete particular import record
		},

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
	}
	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})
	return ret
}

func pathImportQueueList(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "import-queue/",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathFetchImportQueueList,
		},

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
	}
	return ret
}

func (b *backend) pathFetchImportQueueList(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	roles, err := req.Storage.List(ctx, "import-queue/")
	var entries []string
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		log.Printf("%s Getting entry %s", logPrefixVenafiImport, role)
		rawEntry, err := req.Storage.List(ctx, "import-queue/"+role)
		if err != nil {
			return nil, err
		}
		var entry []string
		for _, e := range rawEntry {
			entry = append(entry, fmt.Sprintf("%s: %s", role, e))
		}
		entries = append(entries, entry...)
	}
	return logical.ListResponse(entries), nil
}

func (b *backend) pathUpdateImportQueue(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	roleName := data.Get("role").(string)
	log.Printf("%s Using role: %s", logPrefixVenafiImport, roleName)

	entries, err := req.Storage.List(ctx, "import-queue/"+data.Get("role").(string)+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) fillImportQueueTask(roleName string, noOfWorkers int, storage logical.Storage, importOnlyNonCompliant bool, conf *logical.BackendConfig) {
	ctx := context.Background()
	jobs := make(chan Job, 100)
	replicationState := conf.System.ReplicationState()
	//Checking if we are on master or on the stanby Vault server
	isSlave := !(conf.System.LocalMount() || !replicationState.HasState(hconsts.ReplicationPerformanceSecondary)) ||
		replicationState.HasState(hconsts.ReplicationDRSecondary) ||
		replicationState.HasState(hconsts.ReplicationPerformanceStandby)
	if isSlave {
		log.Printf("%s We're on slave. Sleeping", logPrefixVenafiImport)
		return
	}
	log.Printf("%s We're on master. Starting to import certificates", logPrefixVenafiImport)
	//var err error
	importPath := "import-queue/" + roleName + "/"

	entries, err := storage.List(ctx, importPath)
	if err != nil {
		log.Printf("%s Could not get queue list from path %s: %s", logPrefixVenafiImport, err, importPath)
		return
	}
	log.Printf("%s Queue list on path %s has length %v", logPrefixVenafiImport, importPath, len(entries))

	var wg sync.WaitGroup
	wg.Add(noOfWorkers)
	for i := 0; i < noOfWorkers; i++ {
		go func() {
			defer func() {
				r := recover()
				if r != nil {
					log.Printf("%s recover %s", logPrefixVenafiImport, r)
				}
				wg.Done()
			}()
			for job := range jobs {
				result := b.processImportToTPP(job)
				log.Printf("%s Job id: %d ### Processed entry: %s , result:\n %v\n", logPrefixVenafiImport, job.id, job.entry, result)
			}
		}()
	}
	for i, entry := range entries {
		log.Printf("%s Allocating job for entry %s", logPrefixVenafiImport, entry)
		job := Job{
			id:                     i,
			entry:                  entry,
			importPath:             importPath,
			roleName:               roleName,
			storage:                &storage,
			ctx:                    ctx,
			importOnlyNonCompliant: importOnlyNonCompliant,
		}
		jobs <- job
	}
	close(jobs)
	wg.Wait()
}

func (b *backend) importToTPP(conf *logical.BackendConfig) {

	log.Printf("%s starting importcontroler", logPrefixVenafiImport)
	b.taskStorage.register("importcontroler", func() {
		b.controlImportQueue(conf)
	}, 1, time.Second*1)
}

func (b *backend) controlImportQueue(conf *logical.BackendConfig) {
	log.Printf("%s running control import queue", logPrefixVenafiImport)
	ctx := context.Background()
	const fillQueuePrefix = "fillqueue-"
	roles, err := b.storage.List(ctx, "role/")
	if err != nil {
		log.Printf("%s Couldn't get list of roles %s", logPrefixVenafiImport, err)
		return
	}

	// grab the default to avoid multiple reads for each role
	// there might be a few with custom enforcement config however this will be more complex later
	defaultEnforcementConfig, err := b.getEnforcementConfig(ctx, &b.storage, defaultEnforcementName)
	if err != nil {
		log.Printf("%s error getting default enforcement config %s: %s", logPrefixVenafiImport, defaultEnforcementName, err)
	}

	if defaultEnforcementConfig == nil {
		log.Printf("%s default config for %s is nil.", logPrefixVenafiImport, defaultEnforcementName)
	}

	for i := range roles {
		roleName := roles[i]

		//Update role since it's settings may be changed
		role, err := b.getRole(ctx, b.storage, roleName)
		if err != nil {
			log.Printf("%s exiting due to error getting role %v: %s - %v", logPrefixVenafiImport, role, roleName, err)
			continue
		}

		if role == nil {
			log.Printf("%s exiting due to unknown role %v\n", logPrefixVenafiImport, role)
			continue
		}

		enforcementConfig := defaultEnforcementConfig
		if len(role.CustomEnforcementConfig) > 0 {
			enforcementConfig, err := b.getEnforcementConfig(ctx, &b.storage, role.CustomEnforcementConfig)
			if err != nil || enforcementConfig == nil {
				log.Printf("%s exiting due to error getting custom enforcement config (role config:%s) %v: %v.", logPrefixVenafiImport, role.CustomEnforcementConfig, enforcementConfig, err)
				continue
			}
		}
		if enforcementConfig == nil {
			log.Printf("%s exiting due to missing enforcement config", logPrefixVenafiImport)
			continue
		}

		b.taskStorage.register(fillQueuePrefix+roleName, func() {
			log.Printf("%s run queue filler %s", logPrefixVenafiImport, roleName)
			//get the policy config here, since this is on the scoupe of this anonymous methods, this will
			//solve an issue with the ImportOnlyNonCompliant that doesn't hold the correct value.
			b.fillImportQueueTask(roleName, enforcementConfig.VenafiImportWorkers, b.storage, enforcementConfig.ImportOnlyNonCompliant, conf)
		}, 1, time.Duration(enforcementConfig.VenafiImportTimeout)*time.Second)

	}

	stringInSlice := func(s string, sl []string) bool {
		for i := range sl {
			if sl[i] == s {
				return true
			}
		}
		return false
	}
	for _, taskName := range b.taskStorage.getTasksNames() {
		if strings.HasPrefix(taskName, fillQueuePrefix) && !stringInSlice(strings.TrimPrefix(taskName, fillQueuePrefix), roles) {
			b.taskStorage.del(taskName)
		}
	}
	log.Printf("%s finished running control import queue", logPrefixVenafiImport)
}

func (b *backend) processImportToTPP(job Job) string {

	msg := fmt.Sprintf("Job id: %v ###", job.id)
	importPath := job.importPath

	log.Printf("%s %s Trying to import certificate with SN %s", logPrefixVenafiImport, msg, job.entry)

	role, err := b.getRole(job.ctx, *job.storage, job.roleName)
	if err != nil {
		log.Printf("%s Error getting role %v: %s - %v\n Exiting.", logPrefixVenafiImport, role, job.roleName, err)
		return err.Error()
	}

	if role == nil {
		log.Printf("%s Unknown role (%s) %v\n", logPrefixVenafiImport, job.roleName, role)
		return err.Error()
	}

	cl, _, _, err := role.ClientVenafi(b, job.ctx, job.storage, false, false)
	if err != nil {
		return fmt.Sprintf("%s Could not create venafi client: %s", msg, err)
	}

	certEntry, err := (*job.storage).Get(job.ctx, importPath+job.entry)
	if err != nil {
		return fmt.Sprintf("%s Could not get certificate from %s: %s", msg, importPath+job.entry, err)
	}
	if certEntry == nil {
		return fmt.Sprintf("%s Could not get certificate from %s: cert entry not found", msg, importPath+job.entry)
	}
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certEntry.Value,
	}

	Certificate, err := x509.ParseCertificate(certEntry.Value)
	if err != nil {
		return fmt.Sprintf("%s Could not get certificate from entry %s: %s", msg, importPath+job.entry, err)
	}
	if job.importOnlyNonCompliant {
		valid, err := role.checkCertCompliance(Certificate)
		if err != nil {
			return fmt.Sprintf("Failed checking certificate compliance with policies: %v", err)
		}
		if valid {
			b.deleteCertFromQueue(job)
			return fmt.Sprintf("Skipped import of compliant certificate %v for role %v", job.entry, job.roleName)
		}
	}

	//TODO: here we should check for existing CN and set it to DNS or throw error
	cn := Certificate.Subject.CommonName

	certString := string(pem.EncodeToMemory(&block))
	log.Printf("%s %s Importing cert to %s:\n", logPrefixVenafiImport, msg, cn)

	importReq := &certificate.ImportRequest{
		// if PolicyDN is empty, it is taken from cfg.Zone
		ObjectName:      cn,
		CertificateData: certString,
		PrivateKeyData:  "",
		Password:        "",
		Reconcile:       false,
		CustomFields:    []certificate.CustomField{{Type: certificate.CustomFieldOrigin, Value: "HashiCorp Vault"}},
	}
	importResp, err := cl.ImportCertificate(importReq)
	if err != nil {
		if errors.Is(err, verror.ServerBadDataResponce) || errors.Is(err, verror.UserDataError) {
			//TODO: Here should be renew instead of deletion
			b.deleteCertFromQueue(job)
		}

		///
		if (err != nil) && (cl.GetType() == endpoint.ConnectorTypeTPP) {
			msg := err.Error()

			//catch the scenario when token is expired and deleted.
			var regex = regexp.MustCompile("(expired|invalid)_token")

			//validate if the error is related to a expired access token, at this moment the only way can validate this is using the error message
			//and verify if that message describes errors related to expired access token.
			code := getStatusCode(msg)
			if code == HTTP_UNAUTHORIZED && regex.MatchString(msg) {

				_, cfg, _, err := role.ClientVenafi(b, job.ctx, job.storage, true, true)

				if err != nil {
					return fmt.Sprintf("%s could not import certificate: %s\n", msg, err)
				}

				if cfg.Credentials.RefreshToken != "" {
					msg := fmt.Sprintf("Token will be updated by the Job with id: %v ###", job.id)
					b.Logger().Debug(msg)
					err = synchronizedUpdateAccessToken(cfg, b, job.ctx, job.storage, job.roleName)

					if err != nil {
						return fmt.Sprintf("%s could not import certificate: %s\n", msg, err)
					}

					//everything went fine so get the new client with the new refreshed access token
					cl, _, _, err := role.ClientVenafi(b, job.ctx, job.storage, false, false)
					if err != nil {
						return fmt.Sprintf("%s could not import certificate: %s\n", msg, err)
					}

					b.Logger().Debug("Reading policy configuration again")

					importResp, err = cl.ImportCertificate(importReq)
					if err != nil {
						if errors.Is(err, verror.ServerBadDataResponce) || errors.Is(err, verror.UserDataError) {
							//remove this from current queue, since this is because probably certificate exist on server
							//or user feed certificate with invalid data.
							b.deleteCertFromQueue(job)
						}
						return fmt.Sprintf("%s could not import certificate: %s\n", msg, err)
					} else {
						log.Printf("%s %s Certificate imported:\n %s", logPrefixVenafiImport, msg, pp(importResp))
						b.deleteCertFromQueue(job)
						return pp(importResp)
					}
				} else {
					return fmt.Sprintf("%s could not import certificate: %s\n", msg, err)
				}

			} else {
				return fmt.Sprintf("%s could not import certificate: %s\n", msg, err)
			}
		}
		///

		return fmt.Sprintf("%s could not import certificate: %s\n", msg, err)

	}
	log.Printf("%s %s Certificate imported:\n %s", logPrefixVenafiImport, msg, pp(importResp))
	b.deleteCertFromQueue(job)
	return pp(importResp)

}

func (b *backend) deleteCertFromQueue(job Job) {

	msg := fmt.Sprintf("Job id: %v ###", job.id)
	importPath := job.importPath
	log.Printf("%s %s Removing certificate from import path %s", logPrefixVenafiImport, msg, importPath+job.entry)
	err := (*job.storage).Delete(job.ctx, importPath+job.entry)
	if err != nil {
		log.Printf("%s %s Could not delete %s from queue: %s", logPrefixVenafiImport, msg, importPath+job.entry, err)
	} else {
		log.Printf("%s %s Certificate with SN %s removed from queue", logPrefixVenafiImport, msg, job.entry)
		_, err := (*job.storage).List(job.ctx, importPath)
		if err != nil {
			log.Printf("%s %s Could not get queue list: %s", logPrefixVenafiImport, msg, err)
		}
	}
}

func (b *backend) cleanupImportToTPP(roleName string, ctx context.Context, req *logical.Request) {

	importPath := "import-queue/" + roleName + "/"
	entries, err := req.Storage.List(ctx, importPath)
	if err != nil {
		log.Printf("%s Could not read from queue: %s", logPrefixVenafiImport, err)
	}
	for _, sn := range entries {
		err = req.Storage.Delete(ctx, importPath+sn)
		if err != nil {
			log.Printf("%s Could not delete %s from queue: %s", logPrefixVenafiImport, importPath+sn, err)
		} else {
			log.Printf("%s Deleted %s from queue", logPrefixVenafiImport, importPath+sn)
		}
	}

}

const pathImportQueueSyn = `
Fetch a CA, CRL, CA Chain, or non-revoked certificate.
`

const pathImportQueueDesc = `
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.

Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.

Using "ca_chain" as the value fetches the certificate authority trust chain in PEM encoding.
`
