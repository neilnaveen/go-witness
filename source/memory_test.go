package source

import (
	"encoding/json"
	"fmt"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/testifysec/go-witness/dsse"
	"testing"
)

func TestLoadFile(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr bool
	}{
		{
			name:    "Valid file",
			file:    "testData/dsseEnvelope1.json",
			wantErr: false,
		},
		{
			name:    "Invalid file",
			file:    "testData/nonexistent.json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statement := in_toto.Statement{
				Subject: []in_toto.Subject{
					{
						Name: "example.com/myproject/myartifact",
						Digest: map[string]string{
							"sha256": "6dcd4ce23d88e2ee95838f7b014b6284a3b2a2e4293f8b2a8fd3543f4ab4c4b2",
						},
					},
				},
				Predicate: in_toto.Predicate{
					Type: "https://in-toto.io/Provenance/v0.1",
					Provenance: in_toto.Provenance{
						Builder: in_toto.ProvenanceBuilder{
							ID: "example.com/builders/1",
						},
						Recipe: in_toto.ProvenanceRecipe{
							Type:              "https://example.com/MyBuilder",
							DefinedInMaterial: 0,
						},
						Metadata: in_toto.ProvenanceMetadata{
							BuildStartedOn:  "2022-01-01T00:00:00Z",
							BuildFinishedOn: "2022-01-01T01:00:00Z",
						},
					},
				},
			}

			statementBytes, err := json.Marshal(statement)
			if err != nil {
				fmt.Println("Error marshalling statement:", err)
				return
			}
			envelope := dsse.Envelope{
				Payload:     statementBytes,
				PayloadType: "application/vnd.in-toto+json",
				Signatures: []dsse.Signature{
					{
						KeyID:       "example-key-id",
						Signature:   []byte("example-signature"),
						Certificate: []byte("example-certificate"),
						Intermediates: [][]byte{
							[]byte("example-intermediate-1"),
							[]byte("example-intermediate-2"),
						},
						Timestamps: []dsse.SignatureTimestamp{
							{
								Type: dsse.TimestampRFC3161,
								Data: []byte("example-timestamp-data"),
							},
						},
					},
				},
			}
			memorySource := NewMemorySource()
			err := memorySource.LoadFile(tt.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				_, exists := memorySource.envelopesByReference[tt.file]
				if !exists {
					t.Error("File content was not loaded correctly")
				}
			}
		})
	}
}
