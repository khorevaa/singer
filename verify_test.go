package singer

import (
	"log"
	"os"
	"testing"
)

func TestSing(t *testing.T) {

	singer := KMS{
		ProjectId:  "encoded-stage-295118",
		LocationId: "global",
		KeyRing:    "License",
		Key:        "singerRSA",
		KeyVersion: "1",
	}

	type args struct {
		data []byte
		s    Singer
	}
	tests := []struct {
		name    string
		args    args
		wantSig string
		wantErr bool
	}{
		{
			"test",
			args{
				data: []byte("simple string"),
				s:    singer,
			},
			"",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSig, err := Sing(tt.args.data, tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sing() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			pk := singer.Public()

			err = Verify(pk, tt.args.data, gotSig)

			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}

func TestVerify(t *testing.T) {

	keyOut, err := os.OpenFile("./key.pub", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open <%s> for writing: %v", "./pub", err)
		return
	}

	singer := KMS{
		ProjectId:  "encoded-stage-295118",
		LocationId: "global",
		KeyRing:    "License",
		Key:        "singer",
		KeyVersion: "1",
	}

	singer.SavePublicKey(keyOut)
}
