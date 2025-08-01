package nsm

import (
	"errors"
	"fmt"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

var (
	ErrNSMDeviceAbsent  = fmt.Errorf("nsm: device is absent")
	ErrInvalidPCRIndex  = fmt.Errorf("nsm: invalid PCR index")
	ErrUserDataTooLarge = fmt.Errorf("nsm: user data exceeds maximum size")
	ErrNonceTooLarge    = fmt.Errorf("nsm: nonce exceeds maximum size")
	ErrPubKeyTooLarge   = fmt.Errorf("nsm: public key exceeds maximum size")
	ErrBufferTooLarge   = fmt.Errorf("nsm: buffer exceeds maximum size")
)

const (
	// https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/74a35c70b7b0b855cbb9773178a5c8c5ec405363/source/attestation.c#L20
	NSM_MAX_ATTESTATION_DOC_SIZE = 16 * 1024
	// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
	NSM_MAX_PCR_SIZE           = 64
	NSM_MAX_USER_DATA_SIZE     = 1024
	NSM_MAX_RANDOM_BUFFER_SIZE = 256
)

// Return PCRx condition to be used when creating a KMS key
func PCRxCondition(pcrIndex int) string {
	return fmt.Sprintf("kms:RecipientAttestation:PCR%d", pcrIndex)
}

// Update value of not locked PCRx
//
// PCRx = SHA384(PCRx || data)
func ExtendPCR(pcrIndex int, data []byte) (newPCRValue []byte, err error) {
	if !validatePCRIndex(pcrIndex) {
		return nil, ErrInvalidPCRIndex
	}

	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("failed to open default session: %w", err)
	}
	defer sess.Close()

	res, err := sess.Send(&request.ExtendPCR{
		Index: uint16(pcrIndex),
		Data:  data,
	})
	if err != nil {
		return nil, err
	}

	if res.Error != "" {
		return nil, errors.New(string(res.Error))
	}

	if res.ExtendPCR == nil {
		return nil, errors.New("NSM device did not return an pcr description")
	}

	return res.ExtendPCR.Data, nil
}

func DescribePCR(pcrIndex int) (isLocked bool, data []byte, err error) {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return false, nil, fmt.Errorf("failed to open default session: %w", err)
	}
	defer sess.Close()

	res, err := sess.Send(&request.DescribePCR{
		Index: uint16(pcrIndex),
	})
	if err != nil {
		return false, nil, err
	}

	if res.Error != "" {
		return false, nil, errors.New(string(res.Error))
	}

	if res.DescribePCR == nil {
		return false, nil, errors.New("NSM device did not return an pcr description")
	}

	return res.DescribePCR.Lock, res.DescribePCR.Data, nil
}

// Lock PCRx. Locked PCRs cannot be extended
//
// PCRs 0-15 locked by default
func LockPCR(pcrIndex int) error {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("failed to open default session: %w", err)
	}
	defer sess.Close()

	res, err := sess.Send(&request.LockPCR{
		Index: uint16(pcrIndex),
	})
	if err != nil {
		return err
	}

	if res.Error != "" {
		return errors.New(string(res.Error))
	}

	return nil
}

// Lock range of PCRs: from 0 to pcrsRange
func LockPCRs(pcrsRange int) error {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("failed to open default session: %w", err)
	}
	defer sess.Close()

	res, err := sess.Send(&request.LockPCRs{
		Range: uint16(pcrsRange),
	})
	if err != nil {
		return err
	}

	if res.Error != "" {
		return errors.New(string(res.Error))
	}

	return nil
}

// Get Nitro Secure Module configuration
func GetDescription() (*response.DescribeNSM, error) {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("failed to open default session: %w", err)
	}
	defer sess.Close()

	res, err := sess.Send(&request.DescribeNSM{})
	if err != nil {
		return nil, err
	}

	if res.Error != "" {
		return nil, errors.New(string(res.Error))
	}

	if res.DescribeNSM == nil {
		return nil, errors.New("NSM device did not return an nsm description")
	}

	return res.DescribeNSM, nil
}

func GetAttestationDoc(userData []byte, nonce []byte, pubKey []byte) ([]byte, error) {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("failed to open default session: %w", err)
	}
	defer sess.Close()

	if len(userData) > NSM_MAX_USER_DATA_SIZE {
		return nil, ErrUserDataTooLarge
	}

	if len(nonce) > NSM_MAX_USER_DATA_SIZE {
		return nil, ErrNonceTooLarge
	}

	if len(pubKey) > NSM_MAX_USER_DATA_SIZE {
		return nil, ErrPubKeyTooLarge
	}

	res, err := sess.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  userData,
		PublicKey: pubKey,
	})
	if err != nil {
		return nil, err
	}

	if res.Error != "" {
		return nil, errors.New(string(res.Error))
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("NSM device did not return an attestation")
	}

	return res.Attestation.Document, nil
}

// Get random bytes from NSM up to 256 byte per call
func GetRandom(buf []byte) error {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("failed to open default session: %w", err)
	}
	defer sess.Close()

	if _, err = sess.Read(buf); err != nil {
		return fmt.Errorf("failed to read random data: %w", err)
	}

	return nil
}

func validatePCRIndex(pcrIndex int) bool {
	return pcrIndex >= 0 && pcrIndex <= 31
}
