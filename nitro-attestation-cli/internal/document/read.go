package document

import (
	"bytes"
	"fmt"
	"os"

	"github.com/distributed-lab/enclave-extras/attestation"
	"github.com/distributed-lab/enclave-extras/nsm"
)

type ReadAttestationDocumentOptions struct {
	UserData     bool
	Nonce        bool
	PublicKey    bool
	PCRsToVerify map[int]struct{}
	Input        string
}

func ReadAttestationDocument(opts ReadAttestationDocumentOptions) error {
	attestationDocRaw, err := os.ReadFile(opts.Input)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}
	attestationDoc, err := attestation.ParseNSMAttestationDoc(attestationDocRaw)
	if err != nil {
		return fmt.Errorf("failed to parse attestation document: %w", err)
	}
	if err = attestationDoc.Verify(); err != nil {
		return fmt.Errorf("invalid attestation document signature: %w", err)
	}

	// Verify that PCRs in document same as Enclave PCRs
	for pcr := range opts.PCRsToVerify {
		if _, ok := attestationDoc.PCRs[pcr]; !ok {
			return fmt.Errorf("PCR%d is not in attestation document", pcr)
		}
		isLocked, pcrData, err := nsm.DescribePCR(pcr)
		if err != nil {
			return err
		}
		// If the PCR is not locked, its value can be changed,
		// which means that even if the values are equal now,
		// they may not be equal in the future
		if !isLocked {
			return fmt.Errorf("PCR%d is not locked", pcr)
		}
		if !bytes.Equal(pcrData, attestationDoc.PCRs[pcr]) {
			return fmt.Errorf("PCR%d mismatch with actual PCR%d value", pcr, pcr)
		}
	}

	if opts.UserData {
		fmt.Printf("%s", attestationDoc.UserData)
	}

	if opts.Nonce {
		fmt.Printf("%s", attestationDoc.UserData)
	}

	if opts.PublicKey {
		fmt.Printf("%s", attestationDoc.UserData)
	}
	return nil
}
