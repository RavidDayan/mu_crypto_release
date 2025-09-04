/** @file
  ML-DSA (Module-Lattice-Based Digital Signature Algorithm) API implementation based on OpenSSL

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/BaseCryptLib.h>
#include <Library/DebugLib.h>

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
  ASSERT (FALSE);
  return NULL;
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
  ASSERT (FALSE);
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
  ASSERT (FALSE);
  return FALSE;
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
  ASSERT (FALSE);
  return FALSE;
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
  ASSERT (FALSE);
  return FALSE;
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
  ASSERT (FALSE);
  return FALSE;
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
  ASSERT (FALSE);
  return FALSE;
}
