package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"cloud.google.com/go/storage"
	"github.com/lelandaure/appsecurity/api"
	"github.com/lelandaure/appsecurity/db"
	"github.com/lelandaure/appsecurity/util"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type KeyManagement struct {
	Cnsecurity     string `json:"cn-security"`
	Cnaccount      string `json:"cn-account"`
	Cntransacction string `json:"cn-transaction"`
	Cnmovement     string `json:"cn-movement"`
}

func main() {

	config, err := util.LoadConfig(".")
	if err != nil {
		log.Fatal("cannot load config", err)
	}

	// get storage bucket
	buf := new(bytes.Buffer)
	bucket := "lel-aforo255-bucket"
	object := "config-secret.txt.encrypted"
	Key, err := getKeyManagementServiceValue(buf, bucket, object)
	if err != nil {
		log.Fatal("cannot kms service: ", err.Error())
	}

	fmt.Println("cn security", Key.Cnsecurity)

	conn, err := sql.Open(config.DBDriver, Key.Cnsecurity)
	//log.Println(dataSourceName)
	if err != nil {
		log.Fatal("cannot connect to db", err)
	}
	if err = conn.Ping(); err != nil {
		panic(err)
	}

	store := db.NewStore(conn)
	server, err := api.NewServer(config, store)
	if err != nil {
		log.Fatal("cannot create server", err)
	}

	err = server.Start(config.HTTPServerAddress)
	if err != nil {
		log.Fatal("cannot connect to HTTPServerAddress", err)
	}

}

func getKeyManagementServiceValue(w io.Writer, bucket, object string) (KeyManagement, error) {
	var Key KeyManagement
	// bucket := "bucket-name"
	// object := "object-name"
	ctx := context.Background()
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		return Key, fmt.Errorf("storage.NewClient: %v", err)
	}
	defer storageClient.Close()

	ctx, cancel := context.WithTimeout(ctx, time.Second*50)
	defer cancel()

	storageReader, err := storageClient.Bucket(bucket).Object(object).NewReader(ctx)

	fmt.Println(storageReader.Attrs)
	if err != nil {
		return Key, fmt.Errorf("Object(%q).NewReader: %v", object, err)
	}

	defer storageReader.Close()

	ciphertext, err := ioutil.ReadAll(storageReader)
	if err != nil {
		return Key, fmt.Errorf("ioutil.ReadAll: %v", err)
	}

	// Decryp Values
	nameKey := "projects/my-golang-aforo255-project/locations/global/keyRings/aforo255-kringslel/cryptoKeys/config-keylel"

	// Create the kmsClient.
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return Key, fmt.Errorf("failed to create kms storageClient: %v", err)
	}
	defer client.Close()

	// Get the current IAM policy.
	handle := client.ResourceIAM(nameKey)
	policy, err := handle.Policy(ctx)
	if err != nil {
		return Key, fmt.Errorf("failed to get IAM policy: %v", err)
	}

	// Grant the member permissions. This example grants permission to use the key
	// to encrypt data.
	policy.Add("user:lelandaure@gmail.com", "roles/cloudkms.cryptoKeyEncrypterDecrypter")
	if err := handle.SetPolicy(ctx, policy); err != nil {
		return Key, fmt.Errorf("failed to save policy: %v", err)
	}

	// Optional, but recommended: Compute ciphertext's CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	ciphertextCRC32C := crc32c(ciphertext)

	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:             nameKey,
		Ciphertext:       ciphertext,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
	}

	// Call the API.
	result, err := client.Decrypt(ctx, req)
	if err != nil {
		//reporting(err)
		fmt.Println("the err is: ", err.Error())
		return Key, fmt.Errorf("failed to decrypt ciphertext: %v", err)
	}

	// Optional, but recommended: perform integrity verification on result.
	// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if int64(crc32c(result.Plaintext)) != result.PlaintextCrc32C.Value {
		return Key, fmt.Errorf("Decrypt: response corrupted in-transit")
	}

	emptd := []byte(result.Plaintext)
	json.Unmarshal(emptd, &Key)
	//name := "projects/aforo255-golang/locations/us-central1/keyRings/aforo255-krings2/cryptoKeys/config-key2"

	return Key, nil
}
