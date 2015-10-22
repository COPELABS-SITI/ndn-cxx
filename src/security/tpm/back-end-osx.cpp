/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2015 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "back-end-osx.hpp"
#include "key-handle-osx.hpp"
#include "helper-osx.hpp"
#include "../transform/private-key.hpp"
#include "tpm.hpp"


#include <CoreServices/CoreServices.h>
#include <Security/Security.h>
#include <Security/SecRandom.h>
#include <Security/SecDigestTransform.h>

namespace ndn {
namespace security {
namespace tpm {

class BackEndOsx::Impl
{
public:

  Impl()
    : isTerminalMode(false)
  {
  }

  /**
   * @brief Get private key reference with name @p keyName.
   *
   * @param keyName
   * @returns reference to the key
   */
  CFReleaser<SecKeychainItemRef>
  getKey(const Name& keyName)
  {
    CFReleaser<CFStringRef> keyLabel =
      CFStringCreateWithCString(0,
                                keyName.toUri().c_str(),
                                kCFStringEncodingUTF8);

    CFReleaser<CFMutableDictionaryRef> attrDict =
      CFDictionaryCreateMutable(0,
                                5,
                                &kCFTypeDictionaryKeyCallBacks,
                                0);

    CFDictionaryAddValue(attrDict.get(), kSecClass, kSecClassKey);
    CFDictionaryAddValue(attrDict.get(), kSecAttrLabel, keyLabel.get());
    CFDictionaryAddValue(attrDict.get(), kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionaryAddValue(attrDict.get(), kSecReturnRef, kCFBooleanTrue);

    CFReleaser<SecKeychainItemRef> keyItem;
    // C-style cast is used as per Apple convention
    OSStatus res = SecItemCopyMatching((CFDictionaryRef)attrDict.get(), (CFTypeRef*)&keyItem.get());
    keyItem.retain();

    if (res != errSecSuccess) {
      if (res == errSecAuthFailed) {
        BOOST_THROW_EXCEPTION(Error("Fail to unlock the keychain"));
      }
      BOOST_THROW_EXCEPTION(std::domain_error("Key does not exist"));
    }

    return keyItem;
  }

public:

  SecKeychainRef keyChainRef;
  bool isTerminalMode;
};


static CFTypeRef
getAsymKeyType(KeyType keyType)
{
  switch (keyType) {
  case KeyType::RSA:
    return kSecAttrKeyTypeRSA;
  case KeyType::EC:
    return kSecAttrKeyTypeECDSA;
  default:
    BOOST_THROW_EXCEPTION(Tpm::Error("Unsupported key type"));
  }
}

static CFTypeRef
getDigestAlgorithm(DigestAlgorithm digestAlgo)
{
  switch (digestAlgo) {
  case DigestAlgorithm::SHA256:
    return kSecDigestSHA2;
  default:
    return 0;
  }
}

static long
getDigestSize(DigestAlgorithm digestAlgo)
{
  switch (digestAlgo) {
  case DigestAlgorithm::SHA256:
    return 256;
  default:
    return -1;
  }
}

BackEndOsx::BackEndOsx()
  : m_impl(new Impl)
{
  if (m_impl->isTerminalMode)
    SecKeychainSetUserInteractionAllowed(false);
  else
    SecKeychainSetUserInteractionAllowed(true);

  OSStatus res = SecKeychainCopyDefault(&m_impl->keyChainRef);

  if (res == errSecNoDefaultKeychain) { //If no default key chain, create one.
    BOOST_THROW_EXCEPTION(Error("No default keychain, create one first"));
  }
}

BackEndOsx::~BackEndOsx() = default;

void
BackEndOsx::setTerminalMode(bool isTerminal)
{
  m_impl->isTerminalMode = isTerminal;
  SecKeychainSetUserInteractionAllowed(!isTerminal);
}

bool
BackEndOsx::isTerminalMode() const
{
  return m_impl->isTerminalMode;
}

bool
BackEndOsx::isLocked() const
{
  SecKeychainStatus keychainStatus;

  OSStatus res = SecKeychainGetStatus(m_impl->keyChainRef, &keychainStatus);
  if (res != errSecSuccess)
    return true;
  else
    return ((kSecUnlockStateStatus & keychainStatus) == 0);
}

bool
BackEndOsx::unlockTpm(const char* password, size_t passwordLength)
{
  // If the default key chain is already unlocked, return immediately.
  if (!isLocked())
    return true;

  if (m_impl->isTerminalMode) {
    // Use the supplied password.
    SecKeychainUnlock(m_impl->keyChainRef, passwordLength, password, true);
  }
  else {
    // If inTerminal is not set, get the password from GUI.
    SecKeychainUnlock(m_impl->keyChainRef, 0, nullptr, false);
  }

  return !isLocked();
}

ConstBufferPtr
BackEndOsx::sign(const KeyRefOsx& key, DigestAlgorithm digestAlgorithm,
                 const uint8_t* buf, size_t size) const
{
  CFReleaser<CFDataRef> dataRef = CFDataCreateWithBytesNoCopy(0, buf, size, kCFAllocatorNull);

  CFReleaser<CFErrorRef> error;
  // C-style cast is used as per Apple convention
  CFReleaser<SecTransformRef> signer = SecSignTransformCreate(key.get(), &error.get());
  if (error.get() != 0) {
    BOOST_THROW_EXCEPTION(Error("Fail to create signer"));
  }
  // Set input
  SecTransformSetAttribute(signer.get(),
                           kSecTransformInputAttributeName,
                           dataRef.get(),
                           &error.get());
  if (error.get() != 0) {
    BOOST_THROW_EXCEPTION(Error("Fail to configure input of signer"));
  }
  // Enable use of padding
  SecTransformSetAttribute(signer.get(),
                           kSecPaddingKey,
                           kSecPaddingPKCS1Key,
                           &error.get());
  if (error.get() != 0) {
    BOOST_THROW_EXCEPTION(Error("Fail to configure digest algorithm of signer"));
  }
  // Set padding type
  SecTransformSetAttribute(signer.get(),
                           kSecDigestTypeAttribute,
                           getDigestAlgorithm(digestAlgorithm),
                           &error.get());
  if (error.get() != 0) {
    BOOST_THROW_EXCEPTION(Error("Fail to configure digest algorithm of signer"));
  }
  // Set digest attribute
  long digestSize = getDigestSize(digestAlgorithm);
  CFReleaser<CFNumberRef> cfDigestSize = CFNumberCreate(0, kCFNumberLongType, &digestSize);
  SecTransformSetAttribute(signer.get(),
                           kSecDigestLengthAttribute,
                           cfDigestSize.get(),
                           &error.get());
  if (error.get() != 0) {
    BOOST_THROW_EXCEPTION(Error("Fail to configure digest size of signer"));
  }
  // Actually sign
  // C-style cast is used as per Apple convention
  CFReleaser<CFDataRef> signature = (CFDataRef)SecTransformExecute(signer.get(), &error.get());
  if (error.get() != 0) {
    CFShow(error.get());
    BOOST_THROW_EXCEPTION(Error("Fail to sign data"));
  }

  if (signature.get() == 0) {
    BOOST_THROW_EXCEPTION(Error("Signature is NULL!\n"));
  }

  return make_shared<Buffer>(CFDataGetBytePtr(signature.get()), CFDataGetLength(signature.get()));
}

ConstBufferPtr
BackEndOsx::decrypt(const KeyRefOsx& key, const uint8_t* cipherText, size_t cipherSize) const
{
  CFReleaser<CFDataRef> dataRef = CFDataCreateWithBytesNoCopy(0, cipherText, cipherSize, kCFAllocatorNull);

  CFReleaser<CFErrorRef> error;
  CFReleaser<SecTransformRef> decryptor = SecDecryptTransformCreate(key.get(), &error.get());
  if (error.get() != 0) {
    BOOST_THROW_EXCEPTION(Error("Fail to create decrypt"));
  }
  SecTransformSetAttribute(decryptor.get(),
                           kSecTransformInputAttributeName,
                           dataRef.get(),
                           &error.get());
  if (error.get() != 0) {
    BOOST_THROW_EXCEPTION(Error("Fail to configure decrypt"));
  }
  SecTransformSetAttribute(decryptor.get(),
                           kSecPaddingKey,
                           kSecPaddingOAEPKey,
                           &error.get());

  if (error.get() != 0) {
    BOOST_THROW_EXCEPTION(Error("Fail to configure decrypt #2"));
  }
  CFReleaser<CFDataRef> output = (CFDataRef)SecTransformExecute(decryptor.get(), &error.get());
  if (error.get() != 0) {
    // CFShow(error);
    BOOST_THROW_EXCEPTION(Error("Fail to decrypt data"));
  }

  if (output.get() == 0) {
    BOOST_THROW_EXCEPTION(Error("Output is NULL!\n"));
  }
  return make_shared<Buffer>(CFDataGetBytePtr(output.get()), CFDataGetLength(output.get()));
}

ConstBufferPtr
BackEndOsx::derivePublicKey(const KeyRefOsx& key) const
{
  CFReleaser<CFDataRef> exportedKey;
  OSStatus res = SecItemExport(key.get(),
                               kSecFormatOpenSSL,
                               0,
                               0,
                               &exportedKey.get());

  if (res != errSecSuccess) {
    if (res == errSecAuthFailed) {
      BOOST_THROW_EXCEPTION(Error("Fail to unlock the keychain"));
    }
    else {
      BOOST_THROW_EXCEPTION(Error("Fail to export private key"));
    }
  }

  transform::PrivateKey privateKey;
  privateKey.loadPkcs1(CFDataGetBytePtr(exportedKey.get()), CFDataGetLength(exportedKey.get()));
  return privateKey.derivePublicKey();
}

bool
BackEndOsx::doHasKey(const Name& keyName) const
{
  CFReleaser<CFStringRef> keyLabel =
    CFStringCreateWithCString(0,
                              keyName.toUri().c_str(),
                              kCFStringEncodingUTF8);

  CFReleaser<CFMutableDictionaryRef> attrDict =
    CFDictionaryCreateMutable(0,
                              4,
                              &kCFTypeDictionaryKeyCallBacks,
                              0);

  CFDictionaryAddValue(attrDict.get(), kSecClass, kSecClassKey);
  CFDictionaryAddValue(attrDict.get(), kSecAttrLabel, keyLabel.get());
  CFDictionaryAddValue(attrDict.get(), kSecReturnRef, kCFBooleanTrue);

  CFReleaser<SecKeychainItemRef> itemRef;
  // C-style cast is used as per Apple convention
  OSStatus res = SecItemCopyMatching((CFDictionaryRef)attrDict.get(), (CFTypeRef*)&itemRef.get());
  itemRef.retain();

  return (res == errSecSuccess);
}

unique_ptr<KeyHandle>
BackEndOsx::doGetKeyHandle(const Name& keyName) const
{
  CFReleaser<SecKeychainItemRef> keyItem;
  try {
    keyItem = m_impl->getKey(keyName);
  }
  catch (std::domain_error&) {
    return nullptr;
  }

  return unique_ptr<KeyHandle>(new KeyHandleOsx(*this, (SecKeyRef)keyItem.get()));
}

unique_ptr<KeyHandle>
BackEndOsx::doCreateKey(const Name& identityName, const KeyParams& params)
{
  KeyType keyType = params.getKeyType();
  uint32_t keySize;
  switch (keyType) {
    case KeyType::RSA: {
      const RsaKeyParams& rsaParams = static_cast<const RsaKeyParams&>(params);
      keySize = rsaParams.getKeySize();
      break;
    }
    case KeyType::EC: {
      const EcdsaKeyParams& ecdsaParams = static_cast<const EcdsaKeyParams&>(params);
      keySize = ecdsaParams.getKeySize();
      break;
    }
    default: {
      BOOST_THROW_EXCEPTION(Tpm::Error("Fail to create a key pair: Unsupported key type"));
    }
  }
  CFReleaser<CFNumberRef> cfKeySize = CFNumberCreate(0, kCFNumberIntType, &keySize);

  CFReleaser<CFMutableDictionaryRef> attrDict =
    CFDictionaryCreateMutable(0,
                              2,
                              &kCFTypeDictionaryKeyCallBacks,
                              0);
  CFDictionaryAddValue(attrDict.get(), kSecAttrKeyType, getAsymKeyType(keyType));
  CFDictionaryAddValue(attrDict.get(), kSecAttrKeySizeInBits, cfKeySize.get());

  KeyRefOsx publicKey, privateKey;
  // C-style cast is used as per Apple convention
  OSStatus res = SecKeyGeneratePair((CFDictionaryRef)attrDict.get(),
                                    &publicKey.get(), &privateKey.get());

  BOOST_ASSERT(privateKey.get() != 0);

  publicKey.retain();
  privateKey.retain();

  BOOST_ASSERT(privateKey.get() != 0);

  if (res != errSecSuccess) {
    if (res == errSecAuthFailed) {
      BOOST_THROW_EXCEPTION(Error("Fail to unlock the keychain"));
    }
    else {
      BOOST_THROW_EXCEPTION(Error("Fail to create a key pair"));
    }
  }

  unique_ptr<KeyHandle> keyHandle(new KeyHandleOsx(*this, privateKey.get()));
  setKeyName(*keyHandle, identityName, params);

  SecKeychainAttribute attrs[1]; // maximum number of attributes
  SecKeychainAttributeList attrList = { 0, attrs };
  std::string keyUri = keyHandle->getKeyName().toUri();
  {
    attrs[attrList.count].tag = kSecKeyPrintName;
    attrs[attrList.count].length = keyUri.size();
    attrs[attrList.count].data = const_cast<char*>(keyUri.data());
    attrList.count++;
  }

  res = SecKeychainItemModifyAttributesAndData((SecKeychainItemRef)privateKey.get(),
                                               &attrList,
                                               0,
                                               0);

  res = SecKeychainItemModifyAttributesAndData((SecKeychainItemRef)publicKey.get(),
                                               &attrList,
                                               0,
                                               0);

  return keyHandle;
}

void
BackEndOsx::doDeleteKey(const Name& keyName)
{
  CFReleaser<CFStringRef> keyLabel =
    CFStringCreateWithCString(0,
                              keyName.toUri().c_str(),
                              kCFStringEncodingUTF8);

  CFReleaser<CFMutableDictionaryRef> searchDict =
    CFDictionaryCreateMutable(0,
                              5,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);

  CFDictionaryAddValue(searchDict.get(), kSecClass, kSecClassKey);
  CFDictionaryAddValue(searchDict.get(), kSecAttrLabel, keyLabel.get());
  CFDictionaryAddValue(searchDict.get(), kSecMatchLimit, kSecMatchLimitAll);
  OSStatus res = SecItemDelete(searchDict.get());

  if (res != errSecSuccess) {
    if (res == errSecAuthFailed) {
      BOOST_THROW_EXCEPTION(Error("Fail to unlock the keychain"));
    }
    else if (res != errSecItemNotFound) {
      BOOST_THROW_EXCEPTION(Error("Fail to delete a key pair"));
    }
  }
}

ConstBufferPtr
BackEndOsx::doExportKey(const Name& keyName, const char* pw, size_t pwLen)
{
  CFReleaser<SecKeychainItemRef> privateKey;

  try {
    privateKey = m_impl->getKey(keyName);
  }
  catch (std::domain_error&) {
    BOOST_THROW_EXCEPTION(Tpm::Error("Private key does not exist in OSX Keychain"));
  }

  CFReleaser<CFDataRef> exportedKey;
  SecItemImportExportKeyParameters keyParams;
  memset(&keyParams, 0, sizeof(keyParams));
  CFReleaser<CFStringRef> passphrase = CFStringCreateWithBytes(0,
                                                               reinterpret_cast<const uint8_t*>(pw),
                                                               pwLen,
                                                               kCFStringEncodingUTF8,
                                                               false);
  keyParams.passphrase = passphrase.get();
  OSStatus res = SecItemExport(privateKey.get(),
                               kSecFormatWrappedPKCS8,
                               0,
                               &keyParams,
                               &exportedKey.get());

  if (res != errSecSuccess) {
    if (res == errSecAuthFailed) {
      BOOST_THROW_EXCEPTION(Error("Fail to unlock the keychain"));
    }
    else {
      BOOST_THROW_EXCEPTION(Error("Fail to export private key"));
    }
  }

  return make_shared<Buffer>(CFDataGetBytePtr(exportedKey.get()),
                             CFDataGetLength(exportedKey.get()));
}

void
BackEndOsx::doImportKey(const Name& keyName, const uint8_t* buf, size_t size,
                        const char* pw, size_t pwLen)
{
  CFReleaser<CFDataRef> importedKey =
    CFDataCreateWithBytesNoCopy(0,
                                buf,
                                size,
                                kCFAllocatorNull);

  SecExternalFormat externalFormat = kSecFormatWrappedPKCS8;
  SecExternalItemType externalType = kSecItemTypePrivateKey;

  CFReleaser<CFStringRef> keyLabel = CFStringCreateWithCString(0,
                                                               keyName.toUri().c_str(),
                                                               kCFStringEncodingUTF8);
  CFReleaser<CFStringRef> passphrase = CFStringCreateWithBytes(0,
                                                               reinterpret_cast<const uint8_t*>(pw),
                                                               pwLen,
                                                               kCFStringEncodingUTF8,
                                                               false);
  CFReleaser<SecAccessRef> access;
  SecAccessCreate(keyLabel.get(), 0, &access.get());

  CFArrayRef attributes = 0;

  const SecItemImportExportKeyParameters keyParams {
    SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION, // version
    0, // flags
    passphrase.get(), // pass phrase
    0, // alert title
    0, // alert prompt
    access.get(), // access ref
    0, // key usage
    attributes // key attributes
  };

  CFReleaser<CFArrayRef> outItems;

  OSStatus res = SecItemImport(importedKey.get(),
                               0,
                               &externalFormat,
                               &externalType,
                               0,
                               &keyParams,
                               m_impl->keyChainRef,
                               &outItems.get());

  if (res != errSecSuccess) {
    if (res == errSecAuthFailed) {
      BOOST_THROW_EXCEPTION(Error("Fail to unlock the keychain"));
    }
    else {
      BOOST_THROW_EXCEPTION(Error("Cannot import the private key"));
    }
  }

  // C-style cast is used as per Apple convention
  SecKeychainItemRef privateKey = (SecKeychainItemRef)CFArrayGetValueAtIndex(outItems.get(), 0);
  SecKeychainAttribute attrs[1]; // maximum number of attributes
  SecKeychainAttributeList attrList = { 0, attrs };
  std::string keyUri = keyName.toUri();
  {
    attrs[attrList.count].tag = kSecKeyPrintName;
    attrs[attrList.count].length = keyUri.size();
    attrs[attrList.count].data = const_cast<char*>(keyUri.c_str());
    attrList.count++;
  }

  res = SecKeychainItemModifyAttributesAndData(privateKey,
                                               &attrList,
                                               0,
                                               0);
}

} // namespace tpm
} // namespace security
} // namespace ndn
