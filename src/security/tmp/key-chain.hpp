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

#ifndef NDN_SECURITY_TMP_KEY_CHAIN_HPP
#define NDN_SECURITY_TMP_KEY_CHAIN_HPP

#include "../pib/pib.hpp"
#include "../tpm/tpm.hpp"
#include "../key-params.hpp"
#include "../safe-bag.hpp"
#include "../signing-info.hpp"
#include "certificate.hpp"

#include "../../interest.hpp"
#include "../../util/crypto.hpp"
#include "../../util/random.hpp"
#include <initializer_list>


namespace ndn {
namespace security {
namespace tmp {

/**
 * @brief The interface of signing key management.
 *
 * The KeyChain class provides an interface to manage entities related to packet signing,
 * such as Identity, Key, and Certificates.  It consists of two parts: a private key module
 * (TPM) and a public key information base (PIB).  Managing signing key and its related
 * entities through KeyChain interface guarantees the consistency between TPM and PIB.
 * In other words, users are expected to create and delete keys through the KeyChain
 * interfaces.
 */
class KeyChain : noncopyable
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

  /**
   * @brief Error thrown when the supplied TPM locator to KeyChain constructor does not match
   *        the locator stored in PIB
   */
  class LocatorMismatchError : public Error
  {
  public:
    explicit
    LocatorMismatchError(const std::string& what)
      : Error(what)
    {
    }
  };

  /**
   * @brief Error thrown when the supplied SigningInfo is invalid
   */
  class InvalidSigningInfoError : public Error
  {
  public:
    explicit
    InvalidSigningInfoError(const std::string& what)
      : Error(what)
    {
    }
  };

  /**
   * @brief Constructor to create KeyChain with default PIB and TPM
   *
   * Default PIB and TPM are platform-dependent and can be overriden system-wide or on
   * per-use basis.
   *
   * @todo Add detailed description about config file behavior here
   */
  KeyChain();

  /**
   * @brief KeyChain constructor
   *
   * @sa  http://redmine.named-data.net/issues/2260
   *
   * @param pibLocator
   * @param tpmLocator
   * @param allowReset if true, the PIB will be reset when the supplied tpmLocator
   *        mismatches the one in PIB
   */
  KeyChain(const std::string& pibLocator,
           const std::string& tpmLocator,
           bool allowReset = false);

  ~KeyChain();

public: // PIB & TPM Getter
  Pib&
  getPib()
  {
    return *m_pib;
  }

  const Pib&
  getPib() const
  {
    return *m_pib;
  }

  Tpm&
  getTpm()
  {
    return *m_tpm;
  }

  const Tpm&
  getTpm() const
  {
    return *m_tpm;
  }

public: // Identity Management
  /**
   * @brief Create an identity
   *
   * This method will check if the identity exist in PIB and whether the identity has
   * a default key and default certificate.
   * If the identity does not exist, this method will create the identity in PIB.
   * If the identity's default key does not exist, this method will create a key pair and set it as
   * the identity's default key.
   * If the key's default certificate is missing, this method will create a self-signed certificate
   * for the key.
   *
   * @param identityName The name of the identity.
   * @param params The key parameter if a key needs to be created for the identity.
   * @return The created Identity instance.
   */
  Identity
  createIdentity(const Name& identityName, const KeyParams& params = DEFAULT_KEY_PARAMS);

  /**
   * @brief delete @p identity.
   *
   * @pre @p identity must be valid.
   * @post @p identity becomes invalid.
   */
  void
  deleteIdentity(Identity identity);

  /**
   * @brief Set @p identity as the default identity.
   * @pre @p identity must be valid.
   */
  void
  setDefaultIdentity(Identity identity);

public: // Key Management
  /**
   * @return a key created for @p identity according to @p params
   *
   * This method will also create a self-signed certificate for the created key.
   * @pre @p identity must be valid.
   */
  Key
  createKey(Identity identity, const KeyParams& params = DEFAULT_KEY_PARAMS);

  /**
   * @brief Delete a key @p key of @p identity.
   *
   * @pre @p identity must be valid.
   * @pre @p key must be valid.
   * @post @p key becomes invalid.
   * @throw std::invalid_argument if @p key does not belong to @p identity.
   */
  void
  deleteKey(Identity identity, Key key);

  /**
   * @brief Set @p key as the default key of @p identity.
   *
   * @pre @p identity must be valid.
   * @pre @p key must be valid.
   * @throw std::invalid_argument if @p key does not belong to @p identity.
   */
  void
  setDefaultKey(Identity identity, Key key);

public: // Certificate Management
  /**
   * @brief Add a certificate @p certificate for @p key
   *
   * @pre @p key must be valid.
   * @throw std::invalid_argument if @p key does not match @p certificate.
   * @throw Pib::Error if a certificate with the same name already exists
   */
  void
  addCertificate(Key key, const Certificate& certificate);

  /**
   * @brief delete a certificate with name @p certificateName of @p key.
   *
   * @pre @p key must be valid.
   * @throw std::invalid_argument if @p certificateName does not follow certificate naming convention.
   */
  void
  deleteCertificate(Key key, const Name& certificateName);

  /**
   * @brief Set @p cert as the default certificate of @p key.
   *
   * @pre @p key must be valid.
   */
  void
  setDefaultCertificate(Key key, const Certificate& cert);

public: // signing
  /**
   * @brief Sign data according to the supplied signing information
   *
   * This method uses the supplied signing information @p params to create the SignatureInfo block:
   * - it selects a private key and its certificate to sign the packet
   * - sets the KeyLocator field with the certificate name, and
   * - adds other requested information to the SignatureInfo block.
   *
   * After that, the method assigns the created SignatureInfo to the data packets, generate a
   * signature and sets as part of the SignatureValue block.
   *
   * @pre if the type of @p params is SIGNER_TYPE_PIB_ID or SIGNER_TYPE_PIB_KEY, the corresponding
   * instance must be valid.
   *
   * @param data The data to sign
   * @param params The signing parameters.
   * @throws Error if signing fails.
   * @see SigningInfo
   */
  void
  sign(Data& data, const SigningInfo& params = DEFAULT_SIGNING_INFO);

  /**
   * @brief Sign interest according to the supplied signing information
   *
   * This method uses the supplied signing information @p params to create the SignatureInfo block:
   * - it selects a private key and its certificate to sign the packet
   * - sets the KeyLocator field with the certificate name, and
   * - adds other requested information to the SignatureInfo block.
   *
   * After that, the method appends the created SignatureInfo to the interest name, generate a
   * signature and appends it as part of the SignatureValue block to the interest name.
   *
   * @param interest The interest to sign
   * @param params The signing parameters.
   * @throws Error if signing fails.
   * @see SigningInfo
   * @see docs/specs/signed-interest.rst
   */
  void
  sign(Interest& interest, const SigningInfo& params = DEFAULT_SIGNING_INFO);

  /**
   * @brief Sign buffer according to the supplied signing information @p params
   *
   * If @p params refers to an identity, the method selects the default key of the identity.
   * If @p params refers to a key or certificate, the method select the corresponding key.
   *
   * @param buffer The buffer to sign
   * @param bufferLength The buffer size
   * @param params The signing parameters.
   * @return a SignatureValue TLV block
   * @throws Error if signing fails.
   * @see SigningInfo
   */
  Block
  sign(const uint8_t* buffer, size_t bufferLength,
       const SigningInfo& params = DEFAULT_SIGNING_INFO);

public: // export & import

  /**
   * @brief export a certificate of name @p certificateName and its corresponding private key.
   *
   * @param certificateName The name of certificate to export.
   * @param pw The password to secure the private key.
   * @param pwLen The length of password.
   * @return A SafeBag carrying the certificate and encrypted private key.
   * @throws Error if the certificate or private key does not exist.
   */
  shared_ptr<SafeBag>
  exportSafeBag(const Name& certificateName, const char* pw, size_t pwLen);

  /**
   * @brief Import a pair of certificate and its corresponding private key encapsulated in a SafeBag.
   *
   * If the certificate and key are imported properly, the default setting will be updated as if
   * a new key and certificate is added into KeyChain.
   *
   * @param safeBag The encoded data to import.
   * @param pw The password to secure the private key.
   * @param pwLen The length of password.
   * @throws Error in any of following conditions:
   *         - the safebag cannot be decoded or its content does not match;
   *         - private key cannot be imported;
   *         - a private/public key of the same name already exists;
   *         - a certificate of the same name already exists.
   */
  void
  importSafeBag(const SafeBag& safeBag, const char* pw, size_t pwLen);

public: // public helpers
  /**
   * @brief Get default PIB locator
   */
  static std::string
  getDefaultPibLocator();

  /**
    * @brief Create a PIB according to @p pibLocator
    */
  static unique_ptr<Pib>
  createPib(const std::string& pibLocator);

  /**
   * @brief Get default TPM locator
   */
  static std::string
  getDefaultTpmLocator();

  /**
   * @brief Create a TPM according to @p tpmLocator
   */
  static unique_ptr<Tpm>
  createTpm(const std::string& tpmLocator);

public: // PIB & TPM backend registration

  typedef function<unique_ptr<pib::PibImpl>(const std::string&)> PibCreateFunc;
  typedef function<unique_ptr<tpm::BackEnd>(const std::string&)> TpmCreateFunc;

  /**
   * @brief Register a new PIB backend
   * @param aliases List of schemes with which this PIB backend will be associated.
   *        The first alias is considered the canonical scheme name of PibBackendType.
   */
  template<class PibBackendType>
  static void
  registerPibBackend(std::initializer_list<std::string> aliases);

  /**
   * @brief Register a new TPM backend
   * @param aliases List of schemes with which this TPM backend will be associated
   *        The first alias is considered the canonical scheme name of TpmBackendType.
   */
  template<class TpmBackendType>
  static void
  registerTpmBackend(std::initializer_list<std::string> aliases);

private: // initialization
  static void
  loadDefaultLocators();

  void
  initialize(const std::string& pibLocatorUri,
             const std::string& tpmLocatorUri,
             bool needReset);

  static void
  registerPibBackend(const std::string& canonicalName,
                     std::initializer_list<std::string> aliases, PibCreateFunc createFunc);

  static void
  registerTpmBackend(const std::string& canonicalName,
                     std::initializer_list<std::string> aliases, TpmCreateFunc createFunc);

private: // signing
  /**
   * @brief Generate a self-signed certificate for a public key.
   *
   * The self-signed certificate will also be added into PIB
   *
   * @param keyName The name of the public key
   * @return The generated certificate
   */
  Certificate
  selfSign(Key key);

  /**
   * @brief Prepare a SignatureInfo TLV according to signing information and return the signing key name
   *
   * @param sigInfo The SignatureInfo to prepare.
   * @param params The signing parameters.
   * @return The signing key name and prepared SignatureInfo.
   * @throw InvalidSigningInfoError when the requested signing method cannot be satisfied.
   */
  std::tuple<Name, SignatureInfo>
  prepareSignatureInfo(const SigningInfo& params);

  /**
   * @brief Generate a SignatureValue block for a buffer @p buf with size @p size using
   *        a key with name @p keyName and digest algorithm @p digestAlgorithm.
   */
  Block
  sign(const uint8_t* buf, size_t size, const Name& keyName, DigestAlgorithm digestAlgorithm) const;

  /**
   * @brief Derive SignatureTypeValue according to key type and digest algorithm.
   */
  static tlv::SignatureTypeValue
  getSignatureType(KeyType keyType, DigestAlgorithm digestAlgorithm);

public:
  static const Name DEFAULT_PREFIX;
  static const SigningInfo DEFAULT_SIGNING_INFO;
  static const RsaKeyParams DEFAULT_KEY_PARAMS;

NDN_CXX_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static std::string DEFAULT_PIB_LOCATOR;
  static std::string DEFAULT_TPM_LOCATOR;

private:
  std::unique_ptr<Pib> m_pib;
  std::unique_ptr<Tpm> m_tpm;

  /**
   * @brief cache identities used in signing.
   *
   * Any other methods that modifies identity default key will cause the
   * modified identity to be removed from the cache.  Subsequent signing with
   * the same identity will reload the identity.
   */
  std::unordered_map<Name, Identity> m_signingIdCache;

  /// @brief cache keys used in signing.
  std::unordered_map<Name, Key> m_signingKeyCache;
};

template<class PibType>
inline void
KeyChain::registerPibBackend(std::initializer_list<std::string> aliases)
{
  registerPibBackend(*aliases.begin(), aliases, [] (const std::string& locator) {
      return unique_ptr<pib::PibImpl>(new PibType(locator));
    });
}

template<class TpmType>
inline void
KeyChain::registerTpmBackend(std::initializer_list<std::string> aliases)
{
  registerTpmBackend(*aliases.begin(), aliases, [] (const std::string& locator) {
      return unique_ptr<tpm::BackEnd>(new TpmType(locator));
    });
}

/**
 * @brief Register Pib backend class in KeyChain
 *
 * This macro should be placed once in the implementation file of the
 * Pib backend class within the namespace where the type is declared.
 */
#define NDN_CXX_KEYCHAIN_REGISTER_PIB_BACKEND(PibType, ...)     \
static class NdnCxxAuto ## PibType ## PibRegistrationClass    \
{                                                             \
public:                                                       \
  NdnCxxAuto ## PibType ## PibRegistrationClass()             \
  {                                                           \
    ::ndn::security::tmp::KeyChain::registerPibBackend<PibType>({__VA_ARGS__}); \
  }                                                           \
} ndnCxxAuto ## PibType ## PibRegistrationVariable

/**
 * @brief Register Tpm backend class in KeyChain
 *
 * This macro should be placed once in the implementation file of the
 * Tpm backend class within the namespace where the type is declared.
 */
#define NDN_CXX_KEYCHAIN_REGISTER_TPM_BACKEND(TpmType, ...)     \
static class NdnCxxAuto ## TpmType ## TpmRegistrationClass    \
{                                                             \
public:                                                       \
  NdnCxxAuto ## TpmType ## TpmRegistrationClass()             \
  {                                                           \
    ::ndn::security::tmp::KeyChain::registerTpmBackend<TpmType>({__VA_ARGS__});     \
  }                                                           \
} ndnCxxAuto ## TpmType ## TpmRegistrationVariable

} // namespace tmp
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_TMP_KEY_CHAIN_HPP
