package main

/*
#cgo LDFLAGS: -L${SRCDIR}/../target/lib/ -lnsm
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

int32_t nsm_lib_init();
void nsm_lib_exit(int32_t nsm_fd);
int32_t nsm_extend_pcr(int32_t fd, uint16_t index, const uint8_t* data, uint32_t data_len, uint8_t* pcr_data, uint32_t* pcr_data_len);
int32_t nsm_describe_pcr(int32_t fd, uint16_t index, bool* lock, uint8_t* data, uint32_t* data_len);
int32_t nsm_lock_pcr(int32_t fd, uint16_t index);
int32_t nsm_get_attestation_doc(int32_t nsm_fd,
  const uint8_t* user_data_ptr, uint32_t user_data_len,
  const uint8_t* nonce_data_ptr, uint32_t nonce_len,
  const uint8_t* pub_key_ptr, uint32_t pub_key_size,
  uint8_t* att_doc_data, uint32_t* att_doc_len
);
*/
import "C"

import "unsafe"

type ErrorCode int32

const (
  // No errors
  Success ErrorCode = iota
  // Input argument(s) invalid
  InvalidArgument
  // PlatformConfigurationRegister index out of bounds
  InvalidIndex
  // The received response does not correspond to the earlier request
  InvalidResponse
  // PlatformConfigurationRegister is in read-only mode and the operation
  // attempted to modify it
  ReadOnlyIndex
  // Given request cannot be fulfilled due to missing capabilities
  InvalidOperation
  // Operation succeeded but provided output buffer is too small
  BufferTooSmall
  // The user-provided input is too large
  InputTooLarge
  // NitroSecureModule cannot fulfill request due to internal errors
  InternalError
)

const (
  // https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/74a35c70b7b0b855cbb9773178a5c8c5ec405363/source/attestation.c#L20
  NSM_MAX_ATTESTATION_DOC_SIZE = 16 * 1024
  // https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
  NSM_MAX_PCR_SIZE       = 64
  NSM_MAX_USER_DATA_SIZE = 1024
)

func nsmLibInit() (nsmFd int32) {
  return int32(C.nsm_lib_init())
}

func nsmLibExit(nsmFd int32) {
  C.nsm_lib_exit(C.int32_t(nsmFd))
}

func nsmExtendPCR(nsmFd int32, index uint16, data []byte) ([]byte, ErrorCode) {
  cNSMFd := C.int32_t(nsmFd)
  cIndex := C.uint16_t(index)

  dataPtr := (*C.uint8_t)(unsafe.Pointer(&data[0]))
  dataLen := C.uint32_t(len(data))

  pcrData := make([]byte, NSM_MAX_PCR_SIZE)
  pcrDataPtr := (*C.uint8_t)(unsafe.Pointer(&pcrData[0]))
  pcrDataLen := C.uint32_t(NSM_MAX_PCR_SIZE)

  errorCode := C.nsm_extend_pcr(cNSMFd, cIndex, dataPtr, dataLen, pcrDataPtr, &pcrDataLen)
  return pcrData[:pcrDataLen], ErrorCode(errorCode)
}

func nsmDescribePCR(nsmFd int32, index uint16) (bool, []byte, ErrorCode) {
  cNSMFd := C.int32_t(nsmFd)
  cIndex := C.uint16_t(index)
  cLocked := C.bool(false)

  pcrData := make([]byte, NSM_MAX_PCR_SIZE)
  pcrDataPtr := (*C.uint8_t)(unsafe.Pointer(&pcrData[0]))
  pcrDataLen := C.uint32_t(NSM_MAX_PCR_SIZE)

  errorCode := C.nsm_describe_pcr(cNSMFd, cIndex, &cLocked, pcrDataPtr, &pcrDataLen)
  return bool(cLocked), pcrData[:pcrDataLen], ErrorCode(errorCode)
}

func nsmLockPCR(nsmFd int32, index uint16) ErrorCode {
  cNSMFd := C.int32_t(nsmFd)
  cIndex := C.uint16_t(index)

  errorCode := C.nsm_lock_pcr(cNSMFd, cIndex)
  return ErrorCode(errorCode)
}

func nsmGetAttestationDoc(nsmFd int32, userData []byte, nonce []byte, pubKey []byte) (*NitroAttestationPayload, ErrorCode) {
  attDocRaw, errCode := nsmGetAttestationDocRaw(nsmFd, userData, nonce, pubKey)
  if errCode != Success {
    return nil, errCode
  }
  
  attDoc, err := ParseNitroAttestation(attDocRaw)
  if err != nil {
    return nil, InvalidResponse
  }

  return attDoc, Success
}

func nsmGetAttestationDocRaw(nsmFd int32, userData []byte, nonce []byte, pubKey []byte) ([]byte, ErrorCode) {
  cNSMFd := C.int32_t(nsmFd)

  userDataPtr := (*C.uint8_t)(unsafe.Pointer(&userData[0]))
  userDataLen := C.uint32_t(len(userData))

  noncePtr := (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
  nonceLen := C.uint32_t(len(nonce))

  pubKeyPtr := (*C.uint8_t)(unsafe.Pointer(&pubKey[0]))
  pubKeyLen := C.uint32_t(len(pubKey))

  attestationDoc := make([]byte, NSM_MAX_ATTESTATION_DOC_SIZE)
  attestationDocPtr := (*C.uint8_t)(unsafe.Pointer(&attestationDoc[0]))
  attestationDocLen := C.uint32_t(NSM_MAX_ATTESTATION_DOC_SIZE)

  errorCode := C.nsm_get_attestation_doc(
    cNSMFd,
    userDataPtr, userDataLen,
    noncePtr, nonceLen,
    pubKeyPtr, pubKeyLen,
    attestationDocPtr, &attestationDocLen,
  )
  return attestationDoc[:attestationDocLen], ErrorCode(errorCode)
}
