package attestation

import "fmt"

var (
  ErrNSMDeviceAbsent  = fmt.Errorf("NSM device is absent")
  ErrInvalidPCRIndex  = fmt.Errorf("Invalid PCR index")
  ErrUserDataTooLarge = fmt.Errorf("User data exceeds maximum size")
  ErrNonceTooLarge    = fmt.Errorf("Nonce exceeds maximum size")
  ErrPubKeyTooLarge   = fmt.Errorf("Public key exceeds maximum size")
)

func ExtendPCR(pcrIndex int, data []byte) ([]byte, error) {
  nsmFd := nsmLibInit()
  if nsmFd == -1 {
    return nil, ErrNSMDeviceAbsent
  }

  if !validatePCRIndex(pcrIndex) {
    return nil, ErrInvalidPCRIndex
  }

  extendedPCR, errorCode := nsmExtendPCR(nsmFd, uint16(pcrIndex), data)
  if errorCode != Success {
    return nil, fmt.Errorf("NSM error: %d", errorCode)
  }

  return extendedPCR, nil
}

func DescribePCR(pcrIndex int) (bool, []byte, error) {
  nsmFd := nsmLibInit()
  if nsmFd == -1 {
    return false, nil, ErrNSMDeviceAbsent
  }

  if !validatePCRIndex(pcrIndex) {
    return false, nil, ErrInvalidPCRIndex
  }

  locked, pcrData, errorCode := nsmDescribePCR(nsmFd, uint16(pcrIndex))
  if errorCode != Success {
    return false, nil, fmt.Errorf("NSM error: %d", errorCode)
  }

  return locked, pcrData, nil
}

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
    return fmt.Errorf("NSM error: %d", errorCode)
  }

  return nil
}

func GetAttestationDoc(userData []byte, nonce []byte, pubKey []byte) (*NitroAttestationPayload, error) {
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
    return nil, fmt.Errorf("NSM error: %d", errorCode)
  }

  return attDoc, nil
}

func validatePCRIndex(pcrIndex int) bool {
  return pcrIndex >= 0 && pcrIndex <= 31
}
