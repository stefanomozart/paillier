package paillier

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name    string
		bitsize int
		wantErr bool
	}{
		{
			"bit size smaller then 1024, must return error",
			1023,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk, sk, err := GenerateKeyPair(tt.bitsize)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
