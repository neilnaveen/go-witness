package source

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/testifysec/go-witness/cryptoutil"

	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/dsse"
	intoto "github.com/testifysec/go-witness/intoto"
)

type MockAttestor struct {
	MockName string `json:"mockName"`
}

func (m *MockAttestor) Name() string {
	return m.MockName
}

func (m *MockAttestor) Type() string {
	return "Type1"
}

func (m *MockAttestor) Attestation() ([]byte, error) {
	return []byte("MockAttestation"), nil
}
func (m *MockAttestor) RunType() attestation.RunType {
	return attestation.RunType("MockAttestation")
}
func (m *MockAttestor) Attest(ctx *attestation.AttestationContext) error {
	return fmt.Errorf("ctx file = %v", ctx)
}

type DummyMaterialer struct {
	M map[string]cryptoutil.DigestSet
}

func (DummyMaterialer) Name() string {
	return "dummy-mats"
}

func (DummyMaterialer) Type() string {
	return "dummy-mats"
}

func (DummyMaterialer) RunType() attestation.RunType {
	return attestation.PreMaterialRunType
}

func (DummyMaterialer) Attest(*attestation.AttestationContext) error {
	return nil
}

func (m DummyMaterialer) Materials() map[string]cryptoutil.DigestSet {
	return m.M
}

type DummyProducer struct {
	P map[string]attestation.Product
}

func (DummyProducer) Name() string {
	return "dummy-prods"
}

func (DummyProducer) Type() string {
	return "dummy-prods"
}

func (DummyProducer) RunType() attestation.RunType {
	return attestation.PostProductRunType
}

func (DummyProducer) Attest(*attestation.AttestationContext) error {
	return nil
}

func TestLoadFile(t *testing.T) {

	pred := `{"name":"step1","attestations":[{"type":"dummy-prods","attestation":{"P":{"testfile":{"mime_type":"application/text","digest":{"sha256":"a1073968266a4ed65472a80ebcfd31f1955cfdf8f23d439b1df84d78ce05f7a9"}}}},"starttime":"2023-10-24T12:52:02.711885-05:00","endtime":"2023-10-24T12:53:02.711885-05:00"}]}`
	// validAtt := attestation.Collection{Name: "test", Attestations: []attestation.CollectionAttestation{
	// 	{
	// 		Type:        "dummy-prods",
	// 		Attestation: &DummyProducer{P: map[string]attestation.Product{"product1": attestation.Product{}}},
	// 		StartTime:   time.Now(),
	// 		EndTime:     time.Now(),
	// 	},
	// }}

	//collection := attestation.Collection{}

	// Marshal the collection into a JSON byte array
	// Step 2: Marshal the intoto.Statement into a JSON byte array

	tests := []struct {
		name                string
		reference           string
		intotoStatment      intoto.Statement
		attestations        attestation.Collection
		wantLoadEnvelopeErr bool
		wantPredicateErr    bool
		wantMemorySourceErr bool
	}{
		{
			name:      "Valid intotoStatment",
			reference: "ref",
			intotoStatment: intoto.Statement{
				Type:          "https://in-toto.io/Statement/v0.1",
				Subject:       []intoto.Subject{{Name: "example", Digest: map[string]string{"sha256": "exampledigest"}}},
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Predicate:     json.RawMessage(""),
			},
			wantLoadEnvelopeErr: false,
			wantPredicateErr:    false,
			wantMemorySourceErr: false,
		},
		{
			name:                "Empty Invalid intotoStatment",
			reference:           "ref",
			intotoStatment:      intoto.Statement{},
			wantLoadEnvelopeErr: false,
			wantPredicateErr:    true,
			wantMemorySourceErr: true,
		},
		{
			name:      "Invalid intotoStatment Predicate",
			reference: "ref",
			intotoStatment: intoto.Statement{
				Type:          "https://in-toto.io/Statement/v0.1",
				Subject:       []intoto.Subject{{Name: "example", Digest: map[string]string{"sha256": "exampledigest"}}},
				PredicateType: "https://slsa.dev/provenance/v0.2",
			},
			wantLoadEnvelopeErr: false,
			wantPredicateErr:    true,
			wantMemorySourceErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Marshal the intoto.Statement into a JSON byte array
			var err error

			statementBytes, _ := json.Marshal(tt.intotoStatment)

			// Create a new dsse.Envelope with the marshalled intoto.Statement as the payload
			envelope := dsse.Envelope{
				Payload:     statementBytes,
				PayloadType: "application/vnd.in-toto+json",
			}

			// Initialize a new MemorySource
			memorySource := NewMemorySource()

			if err != nil {
				// if we did not want the error
				if !tt.wantPredicateErr {
					t.Errorf("Failed to unmarshal intoto.Statement's Predicate. Error = %v", err)
					return
				}

				return
			}

			// Load the dsse.Envelope into the MemorySource
			err = memorySource.LoadEnvelope(tt.reference, envelope)
			if err != nil {
				// if we did not want the error
				if !tt.wantLoadEnvelopeErr {
					t.Errorf("LoadEnvelope() error = %v, wantErr %v", err, tt.wantLoadEnvelopeErr)
					return
				}
				return
			}

			// Check if the loaded envelope matches the expected CollectionEnvelope

			expectedCollectionEnvelope := CollectionEnvelope{
				Envelope:   envelope,
				Statement:  tt.intotoStatment,
				Collection: tt.attestations,
				Reference:  tt.reference,
			}
			if !reflect.DeepEqual(memorySource.envelopesByReference[tt.reference], expectedCollectionEnvelope) != tt.wantMemorySourceErr {
				t.Errorf("Mismatch or non-existence of collection envelope for reference in envelopesByReference map.")
				return
			}
			// Verify if the subjects and attestations are present in the loaded envelope
			for _, sub := range tt.intotoStatment.Subject {
				for _, digest := range sub.Digest {
					if _, ok := memorySource.subjectDigestsByReference[tt.reference][digest]; !ok != tt.wantMemorySourceErr {
						t.Errorf("memorySource does not contain passed in digest = %s", digest)
						return
					}
				}
			}
			for _, att := range tt.attestations.Attestations {
				if _, ok := memorySource.attestationsByReference[tt.reference][att.Attestation.Type()]; !ok != tt.wantMemorySourceErr {
					t.Errorf("memorySource does not contain passed in digest = %s", att.Attestation.Name())
					return
				}
			}

		})
	}
}
