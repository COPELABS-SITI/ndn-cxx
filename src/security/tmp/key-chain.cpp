/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2016 Regents of the University of California.
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
 *
 * @author Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>
 */

#include "key-chain.hpp"

#include "../../util/config-file.hpp"

#include "../pib/pib-sqlite3.hpp"
#include "../pib/pib-memory.hpp"

#ifdef NDN_CXX_HAVE_OSX_SECURITY
#include "../tpm/back-end-osx.hpp"
#endif // NDN_CXX_HAVE_OSX_SECURITY

#include "../tpm/back-end-file.hpp"
#include "../tpm/back-end-mem.hpp"

#include "../transform/private-key.hpp"
#include "../transform/buffer-source.hpp"
#include "../transform/verifier-filter.hpp"
#include "../transform/bool-sink.hpp"
#include "../../encoding/buffer-stream.hpp"

namespace ndn {
namespace security {
namespace tmp {

// Use a GUID as a magic number of KeyChain::DEFAULT_PREFIX identifier
const Name KeyChain::DEFAULT_PREFIX("/723821fd-f534-44b3-80d9-44bf5f58bbbb");

// Note: cannot use default constructor, as it depends on static variables which may or may not be
// initialized at this point
const SigningInfo KeyChain::DEFAULT_SIGNING_INFO(SigningInfo::SIGNER_TYPE_NULL, Name(), SignatureInfo());

const RsaKeyParams KeyChain::DEFAULT_KEY_PARAMS;

std::string KeyChain::DEFAULT_PIB_LOCATOR;
std::string KeyChain::DEFAULT_TPM_LOCATOR;


const std::string DEFAULT_PIB_SCHEME = "pib-sqlite3";

#if defined(NDN_CXX_HAVE_OSX_SECURITY) && defined(NDN_CXX_WITH_OSX_KEYCHAIN)
const std::string DEFAULT_TPM_SCHEME = "tpm-osxkeychain";
#else
const std::string DEFAULT_TPM_SCHEME = "tpm-file";
#endif // defined(NDN_CXX_HAVE_OSX_SECURITY) && defined(NDN_CXX_WITH_OSX_KEYCHAIN)

// When static library is used, not everything is compiled into the resulting binary.
// Therefore, the following standard PIB and TPMs need to be registered here.
// http://stackoverflow.com/q/9459980/2150331
//
// Also, cannot use Type::SCHEME, as its value may be uninitialized
using pib::PibSqlite3;
using pib::PibMemory;
NDN_CXX_KEYCHAIN_REGISTER_PIB_BACKEND(PibSqlite3, "pib-sqlite3", "sqlite3");
NDN_CXX_KEYCHAIN_REGISTER_PIB_BACKEND(PibMemory, "pib-memory", "memory");

#ifdef NDN_CXX_HAVE_OSX_SECURITY
using tpm::BackEndOsx;
NDN_CXX_KEYCHAIN_REGISTER_TPM_BACKEND(BackEndOsx, "tpm-osxkeychain", "osx-keychain");
#endif // NDN_CXX_HAVE_OSX_SECURITY

using tpm::BackEndFile;
using tpm::BackEndMem;
NDN_CXX_KEYCHAIN_REGISTER_TPM_BACKEND(BackEndFile, "tpm-file", "file");
NDN_CXX_KEYCHAIN_REGISTER_TPM_BACKEND(BackEndMem, "tpm-memory", "memory");

template<class CreateFunc>
struct Factory
{
  Factory(const std::string& canonicalName, const CreateFunc& create)
    : canonicalName(canonicalName)
    , create(create)
  {
  }

  std::string canonicalName;
  CreateFunc create;
};
typedef Factory<KeyChain::PibCreateFunc> PibFactory;
typedef Factory<KeyChain::TpmCreateFunc> TpmFactory;

static std::map<std::string, PibFactory>&
getPibFactories()
{
  static std::map<std::string, PibFactory> pibFactories;
  return pibFactories;
}

static std::map<std::string, TpmFactory>&
getTpmFactories()
{
  static std::map<std::string, TpmFactory> tpmFactories;
  return tpmFactories;
}

KeyChain::KeyChain()
  : m_pib(nullptr)
  , m_tpm(nullptr)
{
  loadDefaultLocators();
  initialize(DEFAULT_PIB_LOCATOR, DEFAULT_TPM_LOCATOR, true);
}

KeyChain::KeyChain(const std::string& pibName,
                   const std::string& tpmName,
                   bool allowReset)
  : m_pib(nullptr)
  , m_tpm(nullptr)
{
  loadDefaultLocators();
  initialize(pibName, tpmName, allowReset);
}

KeyChain::~KeyChain()
{
}

// public: management

Identity
KeyChain::createIdentity(const Name& identityName, const KeyParams& params)
{
  Identity id = m_pib->addIdentity(identityName);

  Key key;
  try {
    key = id.getDefaultKey();
  }
  catch (const Pib::Error&) {
    key = createKey(id, params);
  }

  try {
    key.getDefaultCertificate();
  }
  catch (const Pib::Error&) {
    selfSign(key);
  }

  return id;
}

void
KeyChain::deleteIdentity(Identity identity)
{
  BOOST_ASSERT(static_cast<bool>(identity));

  Name identityName = identity.getName();

  for (const auto& key : identity.getKeys()) {
    m_signingKeyCache.erase(key.getName());
    m_tpm->deleteKey(key.getName());
  }

  m_signingIdCache.erase(identityName);
  m_pib->removeIdentity(identityName);
}

shared_ptr<SafeBag>
KeyChain::exportSafeBag(const Name& certificateName, const char* pw, size_t pwLen)
{
  Name keyName = toKeyName(certificateName);

  Certificate cert;
  try {
    cert = m_pib->m_impl->getCertificate(certificateName);
  }
  catch (const Pib::Error&) {
    BOOST_THROW_EXCEPTION(Error("certificate does not exist."));
  }

  ConstBufferPtr encryptedKey;
  try {
    encryptedKey = m_tpm->exportPrivateKey(keyName, pw, pwLen);
  }
  catch (tpm::BackEnd::Error&) {
    BOOST_THROW_EXCEPTION(Error("private key does not exist."));
  }

  return make_shared<SafeBag>(cert, *encryptedKey);
}

void
KeyChain::importSafeBag(const SafeBag& safeBag, const char* pw, size_t pwLen)
{
  Data certData = safeBag.getCertificate();
  Certificate cert(std::move(certData));
  Name identity = cert.getIdentity();
  Name keyName = cert.getKeyName();
  const Buffer publicKeyBits = cert.getPublicKey();

  if (m_tpm->hasKey(keyName))
    BOOST_THROW_EXCEPTION(Error("private key already exists."));
  if (m_pib->m_impl->hasCertificate(cert.getName()))
    BOOST_THROW_EXCEPTION(Error("certificate already exists."));
  if (m_pib->m_impl->hasKey(keyName))
    BOOST_THROW_EXCEPTION(Error("public key already exists."));

  try {
    m_tpm->importPrivateKey(keyName,
                            safeBag.getEncryptedKeyBag().buf(),
                            safeBag.getEncryptedKeyBag().size(),
                            pw, pwLen);
  }
  catch (const std::runtime_error&) {
    BOOST_THROW_EXCEPTION(Error("fail to import private key."));
  }

  // check the consistency of private key and certificate
  const uint8_t content[] = {0x01, 0x02, 0x03, 0x04};
  ConstBufferPtr sigBits;
  try {
    sigBits = m_tpm->sign(content, 4, keyName, DigestAlgorithm::SHA256);
  }
  catch (const std::runtime_error&) {
    m_tpm->deleteKey(keyName);
    BOOST_THROW_EXCEPTION(Error("invalid private key."));
  }
  bool isVerified = false;
  {
    using namespace transform;
    PublicKey publicKey;
    publicKey.loadPkcs8(publicKeyBits.buf(), publicKeyBits.size());
    bufferSource(content, sizeof(content)) >> verifierFilter(DigestAlgorithm::SHA256, publicKey,
                                                             sigBits->buf(), sigBits->size())
                                           >> boolSink(isVerified);
  }
  if (!isVerified) {
    m_tpm->deleteKey(keyName);
    BOOST_THROW_EXCEPTION(Error("certificate and private key do not match."));
  }

  Identity id = m_pib->addIdentity(identity);
  Key key = id.addKey(cert.getPublicKey().buf(), cert.getPublicKey().size(), keyName);
  key.addCertificate(cert);
}

void
KeyChain::setDefaultIdentity(Identity identity)
{
  BOOST_ASSERT(static_cast<bool>(identity));

  m_pib->setDefaultIdentity(identity.getName());
}

Key
KeyChain::createKey(Identity identity, const KeyParams& params)
{
  BOOST_ASSERT(static_cast<bool>(identity));

  // create key in TPM
  Name keyName = m_tpm->createKey(identity.getName(), params);

  // set up key info in PIB
  ConstBufferPtr pubKey = m_tpm->getPublicKey(keyName);
  Key key = identity.addKey(pubKey->buf(), pubKey->size(), keyName);
  selfSign(key);

  // since identity property changes, remove it from signingIdCache
  m_signingIdCache.erase(identity.getName());

  return key;
}

void
KeyChain::deleteKey(Identity identity, Key key)
{
  BOOST_ASSERT(static_cast<bool>(identity));
  BOOST_ASSERT(static_cast<bool>(key));

  Name keyName = key.getName();
  if (identity.getName() != key.getIdentity())
    BOOST_THROW_EXCEPTION(std::invalid_argument("identity does match key"));

  identity.removeKey(keyName);
  m_tpm->deleteKey(keyName);

  // since key and identity property changes, remove them from signing cache;
  m_signingKeyCache.erase(keyName);
  m_signingIdCache.erase(identity.getName());
}

void
KeyChain::setDefaultKey(Identity identity, Key key)
{
  BOOST_ASSERT(static_cast<bool>(identity));
  BOOST_ASSERT(static_cast<bool>(key));

  if (identity.getName() != key.getIdentity())
    BOOST_THROW_EXCEPTION(std::invalid_argument("identity does match key"));

  identity.setDefaultKey(key.getName());

  // since identity property changes, remove it from singing cache.
  m_signingIdCache.erase(identity.getName());
}

void
KeyChain::addCertificate(Key key, const Certificate& certificate)
{
  BOOST_ASSERT(static_cast<bool>(key));

  if (key.getName() != certificate.getKeyName() ||
      !std::equal(certificate.getContent().value_begin(), certificate.getContent().value_end(),
                  key.getPublicKey().begin()))
    BOOST_THROW_EXCEPTION(std::invalid_argument("key does match certificate"));

  key.addCertificate(certificate);
}

void
KeyChain::deleteCertificate(Key key, const Name& certificateName)
{
  BOOST_ASSERT(static_cast<bool>(key));

  if (!isCertName(certificateName))
    BOOST_THROW_EXCEPTION(std::invalid_argument("wrong certificate name"));

  key.removeCertificate(certificateName);
}

void
KeyChain::setDefaultCertificate(Key key, const Certificate& cert)
{
  BOOST_ASSERT(static_cast<bool>(key));

  try {
    addCertificate(key, cert);
  }
  catch (const Pib::Error&) { // force to overwrite the existing certificates
    key.removeCertificate(cert.getName());
    addCertificate(key, cert);
  }
  key.setDefaultCertificate(cert.getName());
}


// public: signing

void
KeyChain::sign(Data& data, const SigningInfo& params)
{
  Name keyName;
  SignatureInfo sigInfo;
  std::tie(keyName, sigInfo) = prepareSignatureInfo(params);

  data.setSignature(Signature(sigInfo));

  EncodingBuffer encoder;
  data.wireEncode(encoder, true);

  Block sigValue = sign(encoder.buf(), encoder.size(), keyName, params.getDigestAlgorithm());

  data.wireEncode(encoder, sigValue);
}

void
KeyChain::sign(Interest& interest, const SigningInfo& params)
{
  Name keyName;
  SignatureInfo sigInfo;
  std::tie(keyName, sigInfo) = prepareSignatureInfo(params);

  Name signedName = interest.getName();
  signedName.append(sigInfo.wireEncode()); // signatureInfo

  Block sigValue = sign(signedName.wireEncode().value(),
                        signedName.wireEncode().value_size(),
                        keyName,
                        params.getDigestAlgorithm());

  sigValue.encode();
  signedName.append(sigValue); // signatureValue
  interest.setName(signedName);
}

Block
KeyChain::sign(const uint8_t* buffer, size_t bufferLength, const SigningInfo& params)
{
  Name keyName;
  SignatureInfo sigInfo;
  std::tie(keyName, sigInfo) = prepareSignatureInfo(params);

  return sign(buffer, bufferLength, keyName, params.getDigestAlgorithm());
}

// public: PIB/TPM creation helpers

void
KeyChain::loadDefaultLocators()
{
  if (!DEFAULT_PIB_LOCATOR.empty() && !DEFAULT_TPM_LOCATOR.empty())
    return;

  // first check client.conf.
  ConfigFile config;
  const ConfigFile::Parsed& parsed = config.getParsedConfiguration();

  if (DEFAULT_PIB_LOCATOR.empty()) {
    DEFAULT_PIB_LOCATOR = parsed.get<std::string>("pib", "");
    // if not set in client.conf, take the compilation setting
    if (DEFAULT_PIB_LOCATOR.empty())
      DEFAULT_PIB_LOCATOR = DEFAULT_PIB_SCHEME + ":";
  }

  if (DEFAULT_TPM_LOCATOR.empty()) {
    DEFAULT_TPM_LOCATOR = parsed.get<std::string>("tpm", "");
    // if not set in client.conf, take the compilation setting
    if (DEFAULT_TPM_LOCATOR.empty())
      DEFAULT_TPM_LOCATOR = DEFAULT_TPM_SCHEME + ":";
  }
}

static inline std::tuple<std::string/*type*/, std::string/*location*/>
parseUri(const std::string& uri)
{
  size_t pos = uri.find(':');
  if (pos != std::string::npos) {
    return std::make_tuple(uri.substr(0, pos), uri.substr(pos + 1));
  }
  else {
    return std::make_tuple(uri, "");
  }
}

std::string
KeyChain::getDefaultPibLocator()
{
  loadDefaultLocators();
  return DEFAULT_PIB_LOCATOR;
}

static std::tuple<std::string/*type*/, std::string/*location*/>
getCanonicalPibLocator(const std::string& pibLocator)
{
  std::string pibScheme, pibLocation;
  std::tie(pibScheme, pibLocation) = parseUri(pibLocator);

  if (pibScheme.empty()) {
    pibScheme = DEFAULT_PIB_SCHEME;
  }

  auto pibFactory = getPibFactories().find(pibScheme);
  if (pibFactory == getPibFactories().end()) {
    BOOST_THROW_EXCEPTION(KeyChain::Error("PIB scheme '" + pibScheme + "' is not supported"));
  }
  pibScheme = pibFactory->second.canonicalName;

  return std::make_tuple(pibScheme, pibLocation);
}

unique_ptr<Pib>
KeyChain::createPib(const std::string& pibLocator)
{
  std::string pibScheme, pibLocation;
  std::tie(pibScheme, pibLocation) = getCanonicalPibLocator(pibLocator);
  auto pibFactory = getPibFactories().find(pibScheme);
  BOOST_ASSERT(pibFactory != getPibFactories().end());
  unique_ptr<pib::PibImpl> pibImpl = pibFactory->second.create(pibLocation);
  return unique_ptr<Pib>(new Pib(pibScheme, pibLocation,
                                 shared_ptr<pib::PibImpl>(pibImpl.release())));
}

std::string
KeyChain::getDefaultTpmLocator()
{
  loadDefaultLocators();
  return DEFAULT_TPM_LOCATOR;
}

static std::tuple<std::string/*type*/, std::string/*location*/>
getCanonicalTpmLocator(const std::string& tpmLocator)
{
  std::string tpmScheme, tpmLocation;
  std::tie(tpmScheme, tpmLocation) = parseUri(tpmLocator);

  if (tpmScheme.empty()) {
    tpmScheme = DEFAULT_TPM_SCHEME;
  }
  auto tpmFactory = getTpmFactories().find(tpmScheme);
  if (tpmFactory == getTpmFactories().end()) {
    BOOST_THROW_EXCEPTION(KeyChain::Error("TPM scheme '" + tpmScheme + "' is not supported"));
  }
  tpmScheme = tpmFactory->second.canonicalName;

  return std::make_tuple(tpmScheme, tpmLocation);
}

unique_ptr<Tpm>
KeyChain::createTpm(const std::string& tpmLocator)
{
  std::string tpmScheme, tpmLocation;
  std::tie(tpmScheme, tpmLocation) = getCanonicalTpmLocator(tpmLocator);
  auto tpmFactory = getTpmFactories().find(tpmScheme);
  BOOST_ASSERT(tpmFactory != getTpmFactories().end());
  unique_ptr<tpm::BackEnd> tpmBackEnd = tpmFactory->second.create(tpmLocation);
  return unique_ptr<Tpm>(new Tpm(tpmScheme, tpmLocation,
                                 unique_ptr<tpm::BackEnd>(tpmBackEnd.release())));
}

// private: initialization
void
KeyChain::initialize(const std::string& pibLocator,
                     const std::string& tpmLocator,
                     bool allowReset)
{
  // PIB Locator
  std::string pibScheme, pibLocation;
  std::tie(pibScheme, pibLocation) = getCanonicalPibLocator(pibLocator);
  std::string canonicalPibLocator = pibScheme + ":" + pibLocation;

  // Create PIB
  m_pib = createPib(canonicalPibLocator);
  std::string oldTpmLocator;
  try {
    oldTpmLocator = m_pib->getTpmLocator();
  }
  catch (const Pib::Error&) {
    // TPM locator is not set in PIB yet.
  }

  // TPM Locator
  std::string tpmScheme, tpmLocation;
  std::tie(tpmScheme, tpmLocation) = getCanonicalTpmLocator(tpmLocator);
  std::string canonicalTpmLocator = tpmScheme + ":" + tpmLocation;

  if (canonicalPibLocator == DEFAULT_PIB_LOCATOR) {
    // Default PIB must use default TPM
    if (!oldTpmLocator.empty() && oldTpmLocator != DEFAULT_TPM_LOCATOR) {
      m_pib->reset();
      canonicalTpmLocator = DEFAULT_TPM_LOCATOR;
    }
  }
  else {
    // non-default PIB check consistency
    if (!oldTpmLocator.empty() && oldTpmLocator != canonicalTpmLocator) {
      if (allowReset)
        m_pib->reset();
      else
        BOOST_THROW_EXCEPTION(LocatorMismatchError("TPM locator supplied does not match TPM locator in PIB: " +
                                                   oldTpmLocator + " != " + canonicalTpmLocator));
    }
  }

  // note that key mismatch may still happen if the TPM locator is initially set to a
  // wrong one or if the PIB was shared by more than one TPMs before.  This is due to the
  // old PIB does not have TPM info, new pib should not have this problem.
  m_tpm = createTpm(canonicalTpmLocator);
  m_pib->setTpmLocator(canonicalTpmLocator);
}

void
KeyChain::registerPibBackend(const std::string& canonicalName,
                             std::initializer_list<std::string> aliases,
                             KeyChain::PibCreateFunc createFunc)
{
  for (const std::string& alias : aliases) {
    getPibFactories().emplace(alias, PibFactory(canonicalName, createFunc));
  }
}

void
KeyChain::registerTpmBackend(const std::string& canonicalName,
                             std::initializer_list<std::string> aliases,
                             KeyChain::TpmCreateFunc createFunc)
{
  for (const std::string& alias : aliases) {
    getTpmFactories().emplace(alias, TpmFactory(canonicalName, createFunc));
  }
}

// private: signing

Certificate
KeyChain::selfSign(Key key)
{
  Certificate certificate;

  // set name
  Name certificateName = key.getName();
  certificateName.append("self");
  certificateName.appendVersion();
  certificate.setName(certificateName);

  // set metainfo
  certificate.setContentType(tlv::ContentType_Key);
  certificate.setFreshnessPeriod(time::hours(1));

  // set content
  certificate.setContent(key.getPublicKey().buf(), key.getPublicKey().size());

  // set signature-info
  SignatureInfo sigInfo;
  sigInfo.setKeyLocator(KeyLocator(key.getName()));
  sigInfo.setSignatureType(getSignatureType(key.getKeyType(), DigestAlgorithm::SHA256));
  sigInfo.setValidityPeriod(ValidityPeriod(time::system_clock::now(),
                                           time::system_clock::now() + time::days(365)));
  certificate.setSignature(Signature(sigInfo));

  EncodingBuffer encoder;
  certificate.wireEncode(encoder, true);
  Block sigValue = sign(encoder.buf(), encoder.size(), key.getName(), DigestAlgorithm::SHA256);
  certificate.wireEncode(encoder, sigValue);

  key.addCertificate(certificate);
  return certificate;
}

std::tuple<Name, SignatureInfo>
KeyChain::prepareSignatureInfo(const SigningInfo& params)
{
  SignatureInfo sigInfo = params.getSignatureInfo();

  Name identityName;
  name::Component keyId;
  Name certificateName;

  pib::Identity identity;
  pib::Key key;

  switch (params.getSignerType()) {
    case SigningInfo::SIGNER_TYPE_NULL: {
      try {
        identity = m_pib->getDefaultIdentity();
      }
      catch (const Pib::Error&) { // no default identity, use sha256 for signing.
        sigInfo.setSignatureType(tlv::DigestSha256);
        return std::make_tuple(SigningInfo::DIGEST_SHA256_IDENTITY, sigInfo);
      }
      break;
    }
    case SigningInfo::SIGNER_TYPE_ID: {
      try {
        identity = m_pib->getIdentity(params.getSignerName());
      }
      catch (const Pib::Error&) {
        BOOST_THROW_EXCEPTION(InvalidSigningInfoError("signing identity does not exist"));
      }
      break;
    }
    case SigningInfo::SIGNER_TYPE_KEY: {
      std::tie(identityName, keyId) = parseKeyName(params.getSignerName());
      try {
        identity = m_pib->getIdentity(identityName);
        key = identity.getKey(params.getSignerName());
        identity = Identity(); // we will use the PIB key instance, so reset identity;
      }
      catch (const Pib::Error&) {
        BOOST_THROW_EXCEPTION(InvalidSigningInfoError("signing key does not exist"));
      }
      break;
    }
    case SigningInfo::SIGNER_TYPE_CERT: {
      const Name& keyName = toKeyName(params.getSignerName());
      std::tie(identityName, keyId) = parseKeyName(keyName);
      try {
        identity = m_pib->getIdentity(identityName);
        key = identity.getKey(keyName);
      }
      catch (const Pib::Error&) {
        BOOST_THROW_EXCEPTION(InvalidSigningInfoError("signing key does not exist"));
      }
      sigInfo.setSignatureType(getSignatureType(key.getKeyType(), params.getDigestAlgorithm()));
      sigInfo.setKeyLocator(KeyLocator(params.getSignerName().getPrefix(-1)));
      return std::make_tuple(key.getName(), sigInfo);
    }
    case SigningInfo::SIGNER_TYPE_SHA256: {
      sigInfo.setSignatureType(tlv::DigestSha256);
      return std::make_tuple(SigningInfo::DIGEST_SHA256_IDENTITY, sigInfo);
    }
    case SigningInfo::SIGNER_TYPE_PIB_ID: {
      identity = params.getPibIdentity();
      if (!identity)
        BOOST_THROW_EXCEPTION(InvalidSigningInfoError("PIB Identity is invalid"));
      break;
    }
    case SigningInfo::SIGNER_TYPE_PIB_KEY: {
      key = params.getPibKey();
      if (!key)
        BOOST_THROW_EXCEPTION(InvalidSigningInfoError("PIB Key is invalid"));
      break;
    }
    default:
      BOOST_THROW_EXCEPTION(InvalidSigningInfoError("Unrecognized signer type"));
  }

  if (identity) {
    try {
      key = identity.getDefaultKey();
    }
    catch (const Pib::Error&) {
      BOOST_THROW_EXCEPTION(InvalidSigningInfoError("Signing identity does not have default certificate"));
    }
  }

  if (key) {
    try {
      certificateName = key.getDefaultCertificate().getName();
    }
    catch (const Pib::Error&) {
      certificateName = selfSign(key).getName();
      key.setDefaultCertificate(certificateName);
    }
  }

  sigInfo.setSignatureType(getSignatureType(key.getKeyType(), params.getDigestAlgorithm()));
  sigInfo.setKeyLocator(KeyLocator(certificateName.getPrefix(-1)));
  return std::make_tuple(key.getName(), sigInfo);
}

Block
KeyChain::sign(const uint8_t* buf, size_t size,
               const Name& keyName, DigestAlgorithm digestAlgorithm) const
{
  if (keyName == SigningInfo::DIGEST_SHA256_IDENTITY)
    return Block(tlv::SignatureValue, crypto::sha256(buf, size));

  return Block(tlv::SignatureValue, m_tpm->sign(buf, size, keyName, digestAlgorithm));
}

tlv::SignatureTypeValue
KeyChain::getSignatureType(KeyType keyType, DigestAlgorithm digestAlgorithm)
{
  switch (keyType) {
  case KeyType::RSA:
    return tlv::SignatureSha256WithRsa;
  case KeyType::EC:
    return tlv::SignatureSha256WithEcdsa;
  default:
    BOOST_THROW_EXCEPTION(Error("Unsupported key types"));
  }

}

} // namespace tmp
} // namespace security
} // namespace ndn
