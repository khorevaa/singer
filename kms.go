package singer

import (
	cloudkms "cloud.google.com/go/kms/apiv1"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"io"
	"log"
)

type KMS struct {
	ProjectId  string
	LocationId string
	KeyRing    string
	Key        string
	KeyVersion string
}

func (t KMS) Public() *rsa.PublicKey {

	ctx := context.Background()
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
		t.ProjectId, t.LocationId, t.KeyRing, t.Key, t.KeyVersion)

	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	dresp, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: parentName})
	if err != nil {
		log.Fatal(err)
	}
	pubKeyBlock, _ := pem.Decode([]byte(dresp.Pem))

	pub, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		log.Fatalf("failed to parse public key: " + err.Error())
	}
	publicKey := pub.(*rsa.PublicKey)

	return publicKey
}

func (t KMS) SavePublicKey(keyOut io.Writer) {

	ctx := context.Background()
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
		t.ProjectId, t.LocationId, t.KeyRing, t.Key, t.KeyVersion)

	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	dresp, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: parentName})
	if err != nil {
		log.Fatal(err)
	}

	_, _ = keyOut.Write([]byte(dresp.Pem))
}

func (t KMS) Sing(data []byte) (sig []byte, err error) {

	digest := sha256.Sum256(data)

	ctx := context.Background()
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
		t.ProjectId, t.LocationId, t.KeyRing, t.Key, t.KeyVersion)

	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	req := &kmspb.AsymmetricSignRequest{
		Name: parentName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	}
	dresp, err := kmsClient.AsymmetricSign(ctx, req)

	if err != nil {
		return nil, err
	}

	return dresp.Signature, nil

}
