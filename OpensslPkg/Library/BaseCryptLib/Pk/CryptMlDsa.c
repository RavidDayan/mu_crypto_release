/** @file
  ML-DSA (Module-Lattice-Based Digital Signature Algorithm) API implementation based on OpenSSL

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

// =====================================================================================
//    ML-DSA (Module-Lattice-Based Digital Signature Algorithm) Primitives
// =====================================================================================

/**
  Return the OpenSSL algorithm name for the ML-DSA parameter set.

  @param[in]  MlDsaNid   Identifying number for the ML-DSA parameter set (Defined in
                         BaseCryptLib.h).

  @retval     Algorithm name string for OpenSSL.
  @retval     NULL if parameter set not supported.
**/
STATIC
CONST CHAR8 *
MlDsaNidToOpensslAlgName (
  IN UINTN  MlDsaNid
  )
{
  switch (MlDsaNid) {
    case CRYPTO_NID_ML_DSA_44:
      return "ML-DSA-44";
    case CRYPTO_NID_ML_DSA_65:
      return "ML-DSA-65";
    case CRYPTO_NID_ML_DSA_87:
      return "ML-DSA-87";
    default:
      return NULL;
  }
}

/**
  Allocates and initializes one ML-DSA context for subsequent use.

  @param[in]  MlDsaNid   Identifying number for the ML-DSA parameter set (Defined in
                         BaseCryptLib.h).

  @return  Pointer to the ML-DSA context that has been initialized.
           If the allocations fails, MlDsaNew() returns NULL.
**/
VOID *
EFIAPI
MlDsaNew (
  IN UINTN  MlDsaNid
  )
{
  EVP_PKEY_CTX  *PkeyCtx;
  EVP_PKEY      *Pkey;
  CONST CHAR8   *AlgName;

  AlgName = MlDsaNidToOpensslAlgName (MlDsaNid);
  if (AlgName == NULL) {
    return NULL;
  }

  //
  // Create key generation context
  //
  PkeyCtx = EVP_PKEY_CTX_new_from_name (NULL, AlgName, NULL);
  if (PkeyCtx == NULL) {
    return NULL;
  }

  //
  // Initialize the key generation
  //
  if (EVP_PKEY_keygen_init (PkeyCtx) <= 0) {
    EVP_PKEY_CTX_free (PkeyCtx);
    return NULL;
  }

  //
  // Generate the key pair
  //
  if (EVP_PKEY_generate (PkeyCtx, &Pkey) <= 0) {
    EVP_PKEY_CTX_free (PkeyCtx);
    return NULL;
  }

  EVP_PKEY_CTX_free (PkeyCtx);
  return (VOID *)Pkey;
}

/**
  Release the specified ML-DSA context.

  @param[in]  MlDsaContext  Pointer to the ML-DSA context to be released.
**/
VOID
EFIAPI
MlDsaFree (
  IN  VOID  *MlDsaContext
  )
{
  EVP_PKEY  *Pkey;

  if (MlDsaContext == NULL) {
    return;
  }

  Pkey = (EVP_PKEY *)MlDsaContext;
  EVP_PKEY_free (Pkey);
}

/**
  Generates ML-DSA key pair and returns the public and private keys.

  This function generates random ML-DSA key pair. The caller must make sure 
  RandomSeed() function was properly called before.
  
  If the PublicKey buffer is too small to hold the public key, FALSE is returned and
  PublicKeySize is set to the required buffer size to obtain the public key.
  If the PrivateKey buffer is too small to hold the private key, FALSE is returned and
  PrivateKeySize is set to the required buffer size to obtain the private key.

  For ML-DSA-44, the PublicKeySize is 1312 bytes and PrivateKeySize is 2560 bytes.
  For ML-DSA-65, the PublicKeySize is 1952 bytes and PrivateKeySize is 4032 bytes.
  For ML-DSA-87, the PublicKeySize is 2592 bytes and PrivateKeySize is 4896 bytes.

  If MlDsaContext is NULL, then return FALSE.
  If PublicKeySize is NULL, then return FALSE.
  If PrivateKeySize is NULL, then return FALSE.
  If PublicKeySize is large enough but PublicKey is NULL, then return FALSE.
  If PrivateKeySize is large enough but PrivateKey is NULL, then return FALSE.

  @param[in, out]  MlDsaContext      Pointer to the ML-DSA context.
  @param[out]      PublicKey         Pointer to the buffer to receive generated public key.
  @param[in, out]  PublicKeySize     On input, the size of PublicKey buffer in bytes.
                                     On output, the size of data returned in PublicKey buffer in bytes.
  @param[out]      PrivateKey        Pointer to the buffer to receive generated private key.
  @param[in, out]  PrivateKeySize    On input, the size of PrivateKey buffer in bytes.
                                     On output, the size of data returned in PrivateKey buffer in bytes.

  @retval TRUE   ML-DSA key pair generation succeeded.
  @retval FALSE  ML-DSA key pair generation failed.
  @retval FALSE  PublicKeySize is not large enough.
  @retval FALSE  PrivateKeySize is not large enough.
**/
BOOLEAN
EFIAPI
MlDsaGenerateKey (
  IN OUT  VOID   *MlDsaContext,
  OUT     UINT8  *PublicKey,
  IN OUT  UINTN  *PublicKeySize,
  OUT     UINT8  *PrivateKey,
  IN OUT  UINTN  *PrivateKeySize
  )
{
  EVP_PKEY    *Pkey;
  UINTN       RequiredPubKeySize;
  UINTN       RequiredPrivKeySize;
  UINTN       ActualPubKeySize;
  UINTN       ActualPrivKeySize;
  CONST CHAR8 *AlgName;
  
  if ((MlDsaContext == NULL) || (PublicKeySize == NULL) || (PrivateKeySize == NULL)) {
    return FALSE;
  }

  if (((PublicKey == NULL) && (*PublicKeySize != 0)) ||
      ((PrivateKey == NULL) && (*PrivateKeySize != 0))) {
    return FALSE;
  }

  Pkey = (EVP_PKEY *)MlDsaContext;
  
  //
  // Determine the algorithm name to get required key sizes
  //
  AlgName = EVP_PKEY_get0_type_name (Pkey);
  if (AlgName == NULL) {
    return FALSE;
  }

  //
  // Determine required key sizes based on algorithm
  //
  if (AsciiStrCmp (AlgName, "ML-DSA-44") == 0) {
    RequiredPubKeySize = ML_DSA_44_PUBLIC_KEY_SIZE;
    RequiredPrivKeySize = ML_DSA_44_PRIVATE_KEY_SIZE;
  } else if (AsciiStrCmp (AlgName, "ML-DSA-65") == 0) {
    RequiredPubKeySize = ML_DSA_65_PUBLIC_KEY_SIZE;
    RequiredPrivKeySize = ML_DSA_65_PRIVATE_KEY_SIZE;
  } else if (AsciiStrCmp (AlgName, "ML-DSA-87") == 0) {
    RequiredPubKeySize = ML_DSA_87_PUBLIC_KEY_SIZE;
    RequiredPrivKeySize = ML_DSA_87_PRIVATE_KEY_SIZE;
  } else {
    return FALSE;
  }

  //
  // Check buffer sizes
  //
  if (*PublicKeySize < RequiredPubKeySize) {
    *PublicKeySize = RequiredPubKeySize;
    return FALSE;
  }

  if (*PrivateKeySize < RequiredPrivKeySize) {
    *PrivateKeySize = RequiredPrivKeySize;
    return FALSE;
  }

  //
  // Extract public key
  //
  ActualPubKeySize = *PublicKeySize;
  if (EVP_PKEY_get_raw_public_key (Pkey, PublicKey, (size_t *)&ActualPubKeySize) <= 0) {
    return FALSE;
  }

  //
  // Extract private key
  //
  ActualPrivKeySize = *PrivateKeySize;
  if (EVP_PKEY_get_raw_private_key (Pkey, PrivateKey, (size_t *)&ActualPrivKeySize) <= 0) {
    return FALSE;
  }

  *PublicKeySize = ActualPubKeySize;
  *PrivateKeySize = ActualPrivKeySize;

  return TRUE;
}

/**
  Sets the public key component into the established ML-DSA context.

  @param[in, out]  MlDsaContext      Pointer to ML-DSA context being set.
  @param[in]       PublicKey         Pointer to the buffer to receive generated public key.
  @param[in]       PublicKeySize     The size of PublicKey buffer in bytes.

  @retval  TRUE   ML-DSA public key component was set successfully.
  @retval  FALSE  Invalid ML-DSA public key component or context.
**/
BOOLEAN
EFIAPI
MlDsaSetPublicKey (
  IN OUT  VOID         *MlDsaContext,
  IN      CONST UINT8  *PublicKey,
  IN      UINTN        PublicKeySize
  )
{
  EVP_PKEY      *Pkey;
  EVP_PKEY      *NewPkey;
  CONST CHAR8   *AlgName;
  
  if ((MlDsaContext == NULL) || (PublicKey == NULL)) {
    return FALSE;
  }

  Pkey = (EVP_PKEY *)MlDsaContext;
  
  //
  // Get the algorithm name
  //
  AlgName = EVP_PKEY_get0_type_name (Pkey);
  if (AlgName == NULL) {
    return FALSE;
  }

  //
  // Create new key from raw public key
  //
  NewPkey = EVP_PKEY_new_raw_public_key_ex (NULL, AlgName, NULL, PublicKey, PublicKeySize);
  if (NewPkey == NULL) {
    return FALSE;
  }

  //
  // Replace the key in the context
  //
  EVP_PKEY_free (Pkey);
  *((EVP_PKEY **)MlDsaContext) = NewPkey;

  return TRUE;
}

/**
  Sets the private key component into the established ML-DSA context.

  @param[in, out]  MlDsaContext      Pointer to ML-DSA context being set.
  @param[in]       PrivateKey        Pointer to the buffer to receive generated private key.
  @param[in]       PrivateKeySize    The size of PrivateKey buffer in bytes.

  @retval  TRUE   ML-DSA private key component was set successfully.
  @retval  FALSE  Invalid ML-DSA private key component or context.
**/
BOOLEAN
EFIAPI
MlDsaSetPrivateKey (
  IN OUT  VOID         *MlDsaContext,
  IN      CONST UINT8  *PrivateKey,
  IN      UINTN        PrivateKeySize
  )
{
  EVP_PKEY      *Pkey;
  EVP_PKEY      *NewPkey;
  CONST CHAR8   *AlgName;
  
  if ((MlDsaContext == NULL) || (PrivateKey == NULL)) {
    return FALSE;
  }

  Pkey = (EVP_PKEY *)MlDsaContext;
  
  //
  // Get the algorithm name
  //
  AlgName = EVP_PKEY_get0_type_name (Pkey);
  if (AlgName == NULL) {
    return FALSE;
  }

  //
  // Create new key from raw private key
  //
  NewPkey = EVP_PKEY_new_raw_private_key_ex (NULL, AlgName, NULL, PrivateKey, PrivateKeySize);
  if (NewPkey == NULL) {
    return FALSE;
  }

  //
  // Replace the key in the context
  //
  EVP_PKEY_free (Pkey);
  *((EVP_PKEY **)MlDsaContext) = NewPkey;

  return TRUE;
}

/**
  Carries out the ML-DSA signature.

  This function carries out the ML-DSA signature.
  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  If MlDsaContext is NULL, then return FALSE.
  If Message is NULL, then return FALSE.
  If SigSize is large enough but Signature is NULL, then return FALSE.

  For ML-DSA-44, the SigSize is 2420 bytes.
  For ML-DSA-65, the SigSize is 3309 bytes.
  For ML-DSA-87, the SigSize is 4627 bytes.

  @param[in]       MlDsaContext  Pointer to ML-DSA context for signature generation.
  @param[in]       Message       Pointer to octet message to be signed.
  @param[in]       MessageSize   Size of the message in bytes.
  @param[out]      Signature     Pointer to buffer to receive ML-DSA signature.
  @param[in, out]  SigSize       On input, the size of Signature buffer in bytes.
                                 On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated in ML-DSA.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.
**/
BOOLEAN
EFIAPI
MlDsaSign (
  IN      VOID         *MlDsaContext,
  IN      CONST UINT8  *Message,
  IN      UINTN        MessageSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  EVP_PKEY        *Pkey;
  EVP_MD_CTX      *MdCtx;
  UINTN           ActualSigSize;
  UINTN           RequiredSigSize;
  CONST CHAR8     *AlgName;
  
  if ((MlDsaContext == NULL) || (Message == NULL) || (SigSize == NULL)) {
    return FALSE;
  }

  if ((Signature == NULL) && (*SigSize != 0)) {
    return FALSE;
  }

  Pkey = (EVP_PKEY *)MlDsaContext;
  
  //
  // Get the algorithm name to determine signature size
  //
  AlgName = EVP_PKEY_get0_type_name (Pkey);
  if (AlgName == NULL) {
    return FALSE;
  }

  //
  // Determine required signature size
  //
  if (AsciiStrCmp (AlgName, "ML-DSA-44") == 0) {
    RequiredSigSize = ML_DSA_44_SIGNATURE_SIZE;
  } else if (AsciiStrCmp (AlgName, "ML-DSA-65") == 0) {
    RequiredSigSize = ML_DSA_65_SIGNATURE_SIZE;
  } else if (AsciiStrCmp (AlgName, "ML-DSA-87") == 0) {
    RequiredSigSize = ML_DSA_87_SIGNATURE_SIZE;
  } else {
    return FALSE;
  }

  if (*SigSize < RequiredSigSize) {
    *SigSize = RequiredSigSize;
    return FALSE;
  }

  //
  // Create message digest context
  //
  MdCtx = EVP_MD_CTX_new ();
  if (MdCtx == NULL) {
    return FALSE;
  }

  //
  // Initialize signing operation
  //
  if (EVP_DigestSignInit (MdCtx, NULL, NULL, NULL, Pkey) <= 0) {
    EVP_MD_CTX_free (MdCtx);
    return FALSE;
  }

  //
  // Perform signature
  //
  ActualSigSize = *SigSize;
  if (EVP_DigestSign (MdCtx, Signature, (size_t *)&ActualSigSize, Message, MessageSize) <= 0) {
    EVP_MD_CTX_free (MdCtx);
    return FALSE;
  }

  *SigSize = ActualSigSize;
  EVP_MD_CTX_free (MdCtx);

  return TRUE;
}

/**
  Verifies the ML-DSA signature.

  If MlDsaContext is NULL, then return FALSE.
  If Message is NULL, then return FALSE.
  If Signature is NULL, then return FALSE.

  For ML-DSA-44, the SigSize is 2420 bytes.
  For ML-DSA-65, the SigSize is 3309 bytes.
  For ML-DSA-87, the SigSize is 4627 bytes.

  @param[in]  MlDsaContext  Pointer to ML-DSA context for signature verification.
  @param[in]  Message       Pointer to octet message to be checked.
  @param[in]  MessageSize   Size of the message in bytes.
  @param[in]  Signature     Pointer to ML-DSA signature to be verified.
  @param[in]  SigSize       Size of signature in bytes.

  @retval  TRUE   Valid signature encoded in ML-DSA.
  @retval  FALSE  Invalid signature or invalid ML-DSA context.
**/
BOOLEAN
EFIAPI
MlDsaVerify (
  IN  VOID         *MlDsaContext,
  IN  CONST UINT8  *Message,
  IN  UINTN        MessageSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  )
{
  EVP_PKEY    *Pkey;
  EVP_MD_CTX  *MdCtx;
  INT32       Result;
  
  if ((MlDsaContext == NULL) || (Message == NULL) || (Signature == NULL)) {
    return FALSE;
  }

  if ((SigSize > INT_MAX) || (SigSize == 0)) {
    return FALSE;
  }

  Pkey = (EVP_PKEY *)MlDsaContext;

  //
  // Create message digest context
  //
  MdCtx = EVP_MD_CTX_new ();
  if (MdCtx == NULL) {
    return FALSE;
  }

  //
  // Initialize verification operation
  //
  if (EVP_DigestVerifyInit (MdCtx, NULL, NULL, NULL, Pkey) <= 0) {
    EVP_MD_CTX_free (MdCtx);
    return FALSE;
  }

  //
  // Perform verification
  //
  Result = EVP_DigestVerify (MdCtx, Signature, SigSize, Message, MessageSize);
  
  EVP_MD_CTX_free (MdCtx);

  return (Result == 1);
}
