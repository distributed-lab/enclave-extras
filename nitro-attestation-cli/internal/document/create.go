package document

import (
	"fmt"

	"github.com/distributed-lab/enclave-extras/nsm"
)

type CreateAttestationDocumentOptions struct {
	UserData  []byte
	Nonce     []byte
	PublicKey []byte
}

func CreateAttestationDocument(opts CreateAttestationDocumentOptions) error {
	attestationDoc, err := nsm.GetAttestationDoc(opts.UserData, opts.Nonce, opts.PublicKey)
	if err != nil {
		return err
	}
	fmt.Printf("%s", attestationDoc)
	return nil
}
