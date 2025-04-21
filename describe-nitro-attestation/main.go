package main

import (
	"fmt"
	"os"
	"time"

	"github.com/distributed-lab/enclave-extras/attestation"
)

func main() {
	args := os.Args

	if len(args) == 1 {
		fmt.Println("[E] Provide .coses1 file to describe")
		os.Exit(1)
	}

	filePath := args[1]
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("[E] File does not exist: %s\n", filePath)
			os.Exit(1)
		}
		fmt.Printf("[E] Error checking file: %s\n", err)
		os.Exit(1)
	}

	attestationDocRaw, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[E] Failed to read file: %s\n", err)
		os.Exit(1)
	}

	attestationDoc, err := attestation.ParseNSMAttestationDoc(attestationDocRaw)
	if err != nil {
		fmt.Printf("[E] Failed to read file: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("ModuleID: %s\n", attestationDoc.ModuleID)
	fmt.Printf("Timestamp: %s\n", attestationDoc.Timestamp.Format(time.RFC3339))
	fmt.Printf("Digest: %s\n", attestationDoc.Digest)
	fmt.Printf("PCRs:\n")
	for i := 0; i < 32; i++ {
		measurement, ok := attestationDoc.PCRs[i]
		if !ok {
			continue
		}
		fmt.Printf("\tPCR[%d]: %x\n", i, measurement)
	}
	fmt.Printf("PublicKey: %x\n", attestationDoc.PublicKey)
	fmt.Printf("UserData: %x\n", attestationDoc.UserData)
	fmt.Printf("Nonce: %x\n", attestationDoc.Nonce)
	fmt.Printf("IsValid: %t\n", attestationDoc.Verify() == nil)
}
