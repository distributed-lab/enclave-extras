package nsm

import "fmt"

var (
	ErrNSMDeviceAbsent  = fmt.Errorf("nsm: device is absent")
	ErrInvalidPCRIndex  = fmt.Errorf("nsm: invalid PCR index")
	ErrUserDataTooLarge = fmt.Errorf("nsm: user data exceeds maximum size")
	ErrNonceTooLarge    = fmt.Errorf("nsm: nonce exceeds maximum size")
	ErrPubKeyTooLarge   = fmt.Errorf("nsm: public key exceeds maximum size")
	ErrBufferTooLarge   = fmt.Errorf("nsm: buffer exceeds maximum size")
)

// Return PCRx condition to be used when creating a KMS key
func PCRxCondition(pcrIndex int) string {
	return fmt.Sprintf("kms:RecipientAttestation:PCR%d", pcrIndex)
}

// Update value of not locked PCRx
//
// PCRx = SHA384(PCRx || data)
func ExtendPCR(pcrIndex int, data []byte) (newPCRValue []byte, err error) {
	nsmFd := nsmLibInit()
	if nsmFd == -1 {
		return nil, ErrNSMDeviceAbsent
	}

	if !validatePCRIndex(pcrIndex) {
		return nil, ErrInvalidPCRIndex
	}

	extendedPCR, errorCode := nsmExtendPCR(nsmFd, uint16(pcrIndex), data)
	if errorCode != Success {
		return nil, fmt.Errorf("nsm: error code: %d", errorCode)
	}

	return extendedPCR, nil
}

func DescribePCR(pcrIndex int) (isLocked bool, data []byte, err error) {
	nsmFd := nsmLibInit()
	if nsmFd == -1 {
		return false, nil, ErrNSMDeviceAbsent
	}

	if !validatePCRIndex(pcrIndex) {
		return false, nil, ErrInvalidPCRIndex
	}

	locked, pcrData, errorCode := nsmDescribePCR(nsmFd, uint16(pcrIndex))
	if errorCode != Success {
		return false, nil, fmt.Errorf("nsm: error code: %d", errorCode)
	}

	return locked, pcrData, nil
}

// Lock PCRx. Locked PCRs cannot be extended
//
// PCRs 0-15 locked by default
func LockPCR(pcrIndex int) error {
	nsmFd := nsmLibInit()
	if nsmFd == -1 {
		return ErrNSMDeviceAbsent
	}

	if !validatePCRIndex(pcrIndex) {
		return ErrInvalidPCRIndex
	}

	errorCode := nsmLockPCR(nsmFd, uint16(pcrIndex))
	if errorCode != Success {
		return fmt.Errorf("nsm: error code: %d", errorCode)
	}

	return nil
}

// Lock range of PCRs: from 0 to pcrsRange
func LockPCRs(pcrsRange int) error {
	nsmFd := nsmLibInit()
	if nsmFd == -1 {
		return ErrNSMDeviceAbsent
	}

	if !validatePCRIndex(pcrsRange) {
		return ErrInvalidPCRIndex
	}

	errorCode := nsmLockPCR(nsmFd, uint16(pcrsRange))
	if errorCode != Success {
		return fmt.Errorf("nsm: error code: %d", errorCode)
	}

	return nil
}

// Get Nitro Secure Module configuration
func GetDescription() (*NSMDescription, error) {
	nsmFd := nsmLibInit()
	if nsmFd == -1 {
		return nil, ErrNSMDeviceAbsent
	}

	nsmDescription, errorCode := nsmGetDescription(nsmFd)
	if errorCode != Success {
		return nil, fmt.Errorf("nsm: error code: %d", errorCode)
	}

	return &nsmDescription, nil
}

func GetAttestationDoc(userData []byte, nonce []byte, pubKey []byte) ([]byte, error) {
	nsmFd := nsmLibInit()
	if nsmFd == -1 {
		return nil, ErrNSMDeviceAbsent
	}

	if len(userData) > NSM_MAX_USER_DATA_SIZE {
		return nil, ErrUserDataTooLarge
	}

	if len(nonce) > NSM_MAX_USER_DATA_SIZE {
		return nil, ErrNonceTooLarge
	}

	if len(pubKey) > NSM_MAX_USER_DATA_SIZE {
		return nil, ErrPubKeyTooLarge
	}

	attDoc, errorCode := nsmGetAttestationDoc(nsmFd, userData, nonce, pubKey)
	if errorCode != Success {
		return nil, fmt.Errorf("nsm: error code: %d", errorCode)
	}

	return attDoc, nil
}

// Get random bytes from NSM up to 256 byte per call
func GetRandom(buf []byte) error {
	nsmFd := nsmLibInit()
	if nsmFd == -1 {
		return ErrNSMDeviceAbsent
	}

	if len(buf) > NSM_MAX_RANDOM_BUFFER_SIZE {
		return ErrBufferTooLarge
	}

	errorCode := nsmGetRandom(nsmFd, buf)
	if errorCode != Success {
		return fmt.Errorf("nsm: error code: %d", errorCode)
	}

	return nil
}

func validatePCRIndex(pcrIndex int) bool {
	return pcrIndex >= 0 && pcrIndex <= 31
}
