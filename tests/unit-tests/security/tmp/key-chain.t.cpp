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
 */

#include "security/tmp/key-chain.hpp"
#include "security/transform.hpp"
#include "encoding/buffer-stream.hpp"
#include "../../util/test-home-environment-fixture.hpp"
#include <boost/filesystem.hpp>

#include "boost-test.hpp"

namespace ndn {
namespace security {
namespace tmp {
namespace tests {

BOOST_AUTO_TEST_SUITE(Security)

BOOST_AUTO_TEST_SUITE(Tmp)

BOOST_FIXTURE_TEST_SUITE(TestKeyChain, util::TestHomeEnvironmentFixture)

BOOST_AUTO_TEST_CASE(ConstructorNormalConfig)
{
  KeyChain::DEFAULT_PIB_LOCATOR.clear();
  KeyChain::DEFAULT_TPM_LOCATOR.clear();

  setenv("TEST_HOME", "tests/unit-tests/security/tmp/config-file-home", 1);

  BOOST_REQUIRE_NO_THROW(KeyChain());

  KeyChain keyChain;
  BOOST_CHECK_EQUAL(keyChain.getPib().getPibLocator(),
                    "pib-memory:");
  BOOST_CHECK_EQUAL(keyChain.getPib().getTpmLocator(),
                    "tpm-memory:");
  BOOST_CHECK_EQUAL(keyChain.getTpm().getTpmLocator(),
                    "tpm-memory:");

  unsetenv("TEST_HOME");
}

BOOST_AUTO_TEST_CASE(ConstructorEmptyConfig)
{
  KeyChain::DEFAULT_PIB_LOCATOR.clear();
  KeyChain::DEFAULT_TPM_LOCATOR.clear();

  setenv("TEST_HOME", "tests/unit-tests/security/tmp/config-file-empty-home", 1);

#if defined(NDN_CXX_HAVE_OSX_SECURITY)
  std::string oldHOME;
  if (std::getenv("OLD_HOME"))
    oldHOME = std::getenv("OLD_HOME");

  std::string HOME;
  if (std::getenv("HOME"))
    HOME = std::getenv("HOME");

  if (!oldHOME.empty())
    setenv("HOME", oldHOME.c_str(), 1);
  else
    unsetenv("HOME");
#endif

  BOOST_REQUIRE_NO_THROW(KeyChain());
  KeyChain keyChain;
  BOOST_CHECK_EQUAL(keyChain.getPib().getPibLocator(), "pib-memory:");

#if defined(NDN_CXX_HAVE_OSX_SECURITY)
  BOOST_CHECK_EQUAL(keyChain.getPib().getTpmLocator(), "tpm-osxkeychain:");
  BOOST_CHECK_EQUAL(keyChain.getTpm().getTpmLocator(), "tpm-osxkeychain:");
#else
  BOOST_CHECK_EQUAL(keyChain.getPib().getTpmLocator(), "tpm-file:");
  BOOST_CHECK_EQUAL(keyChain.getTpm().getTpmLocator(), "tpm-file:");
#endif

#if defined(NDN_CXX_HAVE_OSX_SECURITY)
  if (!HOME.empty())
    setenv("HOME", HOME.c_str(), 1);
  else
    unsetenv("HOME");

  if (!oldHOME.empty())
    setenv("OLD_HOME", oldHOME.c_str(), 1);
  else
    unsetenv("OLD_HOME");
#endif
  unsetenv("TEST_HOME");
}

BOOST_AUTO_TEST_CASE(ConstructorEmpty2Config)
{
  KeyChain::DEFAULT_PIB_LOCATOR.clear();
  KeyChain::DEFAULT_TPM_LOCATOR.clear();

  setenv("TEST_HOME", "tests/unit-tests/security/tmp/config-file-empty2-home", 1);

  BOOST_REQUIRE_NO_THROW(KeyChain());

  KeyChain keyChain;
  BOOST_CHECK_EQUAL(keyChain.getPib().getPibLocator(), "pib-sqlite3:");
  BOOST_CHECK_EQUAL(keyChain.getPib().getTpmLocator(), "tpm-memory:");
  BOOST_CHECK_EQUAL(keyChain.getTpm().getTpmLocator(), "tpm-memory:");
  unsetenv("TEST_HOME");
}

BOOST_AUTO_TEST_CASE(ConstructorMalConfig)
{
  KeyChain::DEFAULT_PIB_LOCATOR.clear();
  KeyChain::DEFAULT_TPM_LOCATOR.clear();

  setenv("TEST_HOME", "tests/unit-tests/security/tmp/config-file-malformed-home", 1);
  BOOST_REQUIRE_THROW(KeyChain(), KeyChain::Error); // Wrong configuration. Error expected.
  unsetenv("TEST_HOME");
}

BOOST_AUTO_TEST_CASE(ConstructorMal2Config)
{
  KeyChain::DEFAULT_PIB_LOCATOR.clear();
  KeyChain::DEFAULT_TPM_LOCATOR.clear();

  setenv("TEST_HOME", "tests/unit-tests/security/tmp/config-file-malformed2-home", 1);
  BOOST_REQUIRE_THROW(KeyChain(), KeyChain::Error); // Wrong configuration. Error expected.
  unsetenv("TEST_HOME");
}

BOOST_AUTO_TEST_CASE(Management)
{
  KeyChain keyChain("pib-memory:", "tpm-memory:");
  Name identityName("/test/id");
  Name identity2Name("/test/id2");

  BOOST_CHECK(keyChain.getPib().getIdentities().find(identityName) == keyChain.getPib().getIdentities().end());
  BOOST_REQUIRE_THROW(keyChain.getPib().getDefaultIdentity(), Pib::Error);

  // Create identity
  Identity id = keyChain.createIdentity(identityName);
  BOOST_CHECK(id);
  BOOST_CHECK(keyChain.getPib().getIdentities().find(identityName) != keyChain.getPib().getIdentities().end());
  // The first added identity becomes the default identity
  BOOST_REQUIRE_NO_THROW(keyChain.getPib().getDefaultIdentity());
  // The default key of the added identity must exist
  BOOST_REQUIRE_NO_THROW(id.getDefaultKey());
  Key key = id.getDefaultKey();
  // The default certificate of the default key must exist
  BOOST_REQUIRE_NO_THROW(key.getDefaultCertificate());
  Name key1Name = key.getName();

  // Delete key
  BOOST_CHECK_NO_THROW(id.getKey(key1Name));
  BOOST_CHECK_EQUAL(id.getKeys().size(), 1);
  keyChain.deleteKey(id, key);
  // The key instance should not be valid any more
  BOOST_CHECK(!key);
  BOOST_CHECK_THROW(id.getKey(key1Name), Pib::Error);
  BOOST_CHECK_EQUAL(id.getKeys().size(), 0);

  // Create another key
  keyChain.createKey(id);
  // The added key becomes the default key.
  BOOST_REQUIRE_NO_THROW(id.getDefaultKey());
  Key key2 = id.getDefaultKey();
  BOOST_REQUIRE(key2);
  BOOST_CHECK(key2.getName() != key1Name);
  BOOST_CHECK_EQUAL(id.getKeys().size(), 1);
  BOOST_REQUIRE_NO_THROW(key2.getDefaultCertificate());
  Data key2Cert1 = key2.getDefaultCertificate();

  // Create the third key
  Key key3 = keyChain.createKey(id);
  BOOST_CHECK(key3.getName() != key2.getName());
  // The added key will not be the default key, because the default key already exists
  BOOST_CHECK(id.getDefaultKey().getName() == key2.getName());
  BOOST_CHECK_EQUAL(id.getKeys().size(), 2);
  BOOST_REQUIRE_NO_THROW(key3.getDefaultCertificate());

  // Delete cert
  BOOST_CHECK_EQUAL(key3.getCertificates().size(), 1);
  Certificate key3Cert1 = *key3.getCertificates().begin();
  Name key3CertName = key3Cert1.getName();
  keyChain.deleteCertificate(key3, key3CertName);
  BOOST_CHECK_EQUAL(key3.getCertificates().size(), 0);
  BOOST_REQUIRE_THROW(key3.getDefaultCertificate(), Pib::Error);

  // Add cert
  keyChain.addCertificate(key3, key3Cert1);
  BOOST_CHECK_EQUAL(key3.getCertificates().size(), 1);
  BOOST_REQUIRE_NO_THROW(key3.getDefaultCertificate());
  // Overwrite the same cert again, should throw Pib::Error.
  BOOST_REQUIRE_THROW(keyChain.addCertificate(key3, key3Cert1), Pib::Error);
  BOOST_CHECK_EQUAL(key3.getCertificates().size(), 1);
  // Add another cert
  Certificate key3Cert2 = key3Cert1;
  Name key3Cert2Name = key3.getName();
  key3Cert2Name.append("Self");
  key3Cert2Name.appendVersion();
  key3Cert2.setName(key3Cert2Name);
  keyChain.addCertificate(key3, key3Cert2);
  BOOST_CHECK_EQUAL(key3.getCertificates().size(), 2);

  // Default certificate setting
  BOOST_CHECK_EQUAL(key3.getDefaultCertificate().getName(), key3CertName);
  keyChain.setDefaultCertificate(key3, key3Cert2);
  BOOST_CHECK_EQUAL(key3.getDefaultCertificate().getName(), key3Cert2Name);

  // Default key setting
  BOOST_CHECK_EQUAL(id.getDefaultKey().getName(), key2.getName());
  keyChain.setDefaultKey(id, key3);
  BOOST_CHECK_EQUAL(id.getDefaultKey().getName(), key3.getName());

  // Default identity setting
  Identity id2 = keyChain.createIdentity(identity2Name);
  BOOST_CHECK_EQUAL(keyChain.getPib().getDefaultIdentity().getName(), id.getName());
  keyChain.setDefaultIdentity(id2);
  BOOST_CHECK_EQUAL(keyChain.getPib().getDefaultIdentity().getName(), id2.getName());

  // Delete identity
  keyChain.deleteIdentity(id);
  // The identity instance should not be valid any more
  BOOST_CHECK(!id);
  BOOST_REQUIRE_THROW(keyChain.getPib().getIdentity(identityName), Pib::Error);
  BOOST_CHECK(keyChain.getPib().getIdentities().find(identityName) == keyChain.getPib().getIdentities().end());
}

BOOST_AUTO_TEST_CASE(ExportImport)
{
  KeyChain keyChain("pib-memory:", "tpm-memory:");

  Identity id = keyChain.createIdentity(Name("/TestKeyChain/ExportIdentity/"));
  Certificate cert = id.getDefaultKey().getDefaultCertificate();

  shared_ptr<SafeBag> exported = keyChain.exportSafeBag(cert.getName(), "1234", 4);
  Block block = exported->wireEncode();

  keyChain.deleteIdentity(id);

  BOOST_CHECK_EQUAL(keyChain.getTpm().hasKey(cert.getKeyName()), false);
  BOOST_CHECK_EQUAL(keyChain.getPib().getIdentities().size(), 0);

  SafeBag imported;
  imported.wireDecode(block);
  keyChain.importSafeBag(imported, "1234", 4);

  BOOST_CHECK_EQUAL(keyChain.getTpm().hasKey(cert.getKeyName()), true);
  BOOST_CHECK_EQUAL(keyChain.getPib().getIdentities().size(), 1);
  BOOST_REQUIRE_NO_THROW(keyChain.getPib().getIdentity(cert.getIdentity()));
  Identity newId = keyChain.getPib().getIdentity(cert.getIdentity());
  BOOST_CHECK_EQUAL(newId.getKeys().size(), 1);
  BOOST_REQUIRE_NO_THROW(newId.getKey(cert.getKeyName()));
  Key newKey = newId.getKey(cert.getKeyName());
  BOOST_CHECK_EQUAL(newKey.getCertificates().size(), 1);
  BOOST_REQUIRE_NO_THROW(newKey.getCertificate(cert.getName()));

  keyChain.deleteIdentity(newId);
  BOOST_CHECK_EQUAL(keyChain.getPib().getIdentities().size(), 0);
  BOOST_CHECK_EQUAL(keyChain.getTpm().hasKey(cert.getKeyName()), false);
}

BOOST_AUTO_TEST_CASE(KeyChainWithCustomTpmAndPib)
{
  BOOST_REQUIRE_NO_THROW((KeyChain("pib-memory", "tpm-memory")));
  BOOST_REQUIRE_NO_THROW((KeyChain("memory", "memory")));
  BOOST_REQUIRE_NO_THROW((KeyChain("memory:", "memory:")));
  BOOST_REQUIRE_NO_THROW((KeyChain("memory:/something", "memory:/something")));

  KeyChain keyChain("memory", "memory");
  BOOST_CHECK_EQUAL(keyChain.getPib().getPibLocator(), "pib-memory:");
  BOOST_CHECK_EQUAL(keyChain.getPib().getTpmLocator(), "tpm-memory:");
  BOOST_CHECK_EQUAL(keyChain.getTpm().getTpmLocator(), "tpm-memory:");
}

bool
verifySignature(const uint8_t* data, size_t dataLen,
                const uint8_t* sig, size_t sigLen,
                const Buffer& key)
{
  using namespace transform;

  PublicKey pKey;
  bool result = false;
  pKey.loadPkcs8(key.buf(), key.size());
  bufferSource(data, dataLen) >> verifierFilter(DigestAlgorithm::SHA256, pKey, sig, sigLen) >> boolSink(result);

  return result;
}

bool
verifySignature(const Data& data, const Buffer& key)
{
  return verifySignature(data.wireEncode().value(), data.wireEncode().value_size() - data.getSignature().getValue().size(),
                         data.getSignature().getValue().value(), data.getSignature().getValue().value_size(),
                         key);
}

bool
verifySignature(const Interest& interest, const Buffer& key)
{
  const Name& interestName = interest.getName();
  const Block& nameBlock = interestName.wireEncode();
  const Block& sigValue = interestName[-1].blockFromValue();

  return verifySignature(nameBlock.value(), nameBlock.value_size() - interestName[-1].size(),
                         sigValue.value(), sigValue.value_size(),
                         key);
}

bool
verifySha256Digest(const uint8_t* data, size_t dataLen,
                   const uint8_t* sig, size_t sigLen)
{
  using namespace transform;

  OBufferStream os;
  bufferSource(data, dataLen) >> digestFilter(DigestAlgorithm::SHA256) >> streamSink(os);
  ConstBufferPtr digest = os.buf();

  return std::equal(digest->begin(), digest->end(), sig);
}

bool
verifySha256Digest(const Data& data)
{
  return verifySha256Digest(data.wireEncode().value(), data.wireEncode().value_size() - data.getSignature().getValue().size(),
                            data.getSignature().getValue().value(), data.getSignature().getValue().value_size());
}

bool
verifySha256Digest(const Interest& interest)
{
  const Name& interestName = interest.getName();
  const Block& nameBlock = interestName.wireEncode();
  const Block& sigValue = interestName[-1].blockFromValue();

  return verifySha256Digest(nameBlock.value(), nameBlock.value_size() - interestName[-1].size(),
                            sigValue.value(), sigValue.value_size());
}

BOOST_AUTO_TEST_CASE(GeneralSigningInterface)
{
  KeyChain keyChain("pib-memory:", "tpm-memory:");

  Name idName("/id");
  Identity id = keyChain.createIdentity(idName);
  Name id2Name("/id2");
  Identity id2 = keyChain.createIdentity(id2Name);

  // SigningInfo is set to default
  Data data1("/data1");
  keyChain.sign(data1);
  BOOST_CHECK_EQUAL(data1.getSignature().getKeyLocator().getName(),
                    id.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(data1, id.getDefaultKey().getPublicKey()));

  Interest interest1("/interest1");
  keyChain.sign(interest1);
  SignatureInfo sigInfo1(interest1.getName()[-2].blockFromValue());
  BOOST_CHECK_EQUAL(sigInfo1.getKeyLocator().getName(),
                    id.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(interest1, id.getDefaultKey().getPublicKey()));

  // SigningInfo is set to identity name
  Data data2("/data2");
  keyChain.sign(data2, SigningInfo(SigningInfo::SIGNER_TYPE_ID, id2.getName()));
  BOOST_CHECK_EQUAL(data2.getSignature().getKeyLocator().getName(),
                    id2.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(data2, id2.getDefaultKey().getPublicKey()));

  Interest interest2("/interest2");
  keyChain.sign(interest2, SigningInfo(SigningInfo::SIGNER_TYPE_ID, id2.getName()));
  SignatureInfo sigInfo2(interest2.getName()[-2].blockFromValue());
  BOOST_CHECK_EQUAL(sigInfo2.getKeyLocator().getName(),
                    id2.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(interest2, id2.getDefaultKey().getPublicKey()));

  // SigningInfo is set to key name
  Data data3("/data3");
  keyChain.sign(data3, SigningInfo(SigningInfo::SIGNER_TYPE_KEY, id.getDefaultKey().getName()));
  BOOST_CHECK_EQUAL(data3.getSignature().getKeyLocator().getName(),
                    id.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(data3, id.getDefaultKey().getPublicKey()));

  Interest interest3("/interest3");
  keyChain.sign(interest3, SigningInfo(SigningInfo::SIGNER_TYPE_KEY, id.getDefaultKey().getName()));
  SignatureInfo sigInfo3(interest3.getName()[-2].blockFromValue());
  BOOST_CHECK_EQUAL(sigInfo3.getKeyLocator().getName(),
                    id.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(interest3, id.getDefaultKey().getPublicKey()));

  // SigningInfo is set to cert name
  Data data4("/data4");
  keyChain.sign(data4, SigningInfo(SigningInfo::SIGNER_TYPE_CERT,
                                   id.getDefaultKey().getDefaultCertificate().getName()));
  BOOST_CHECK_EQUAL(data4.getSignature().getKeyLocator().getName(),
                    id.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(data4, id.getDefaultKey().getPublicKey()));

  Interest interest4("/interest4");
  keyChain.sign(interest4, SigningInfo(SigningInfo::SIGNER_TYPE_CERT,
                                       id.getDefaultKey().getDefaultCertificate().getName()));
  SignatureInfo sigInfo4(interest4.getName()[-2].blockFromValue());
  BOOST_CHECK_EQUAL(sigInfo4.getKeyLocator().getName(),
                    id.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(interest4, id.getDefaultKey().getPublicKey()));

  // SigningInfo is set to DigestSha256
  Data data5("/data5");
  keyChain.sign(data5, SigningInfo(SigningInfo::SIGNER_TYPE_SHA256));
  BOOST_CHECK(verifySha256Digest(data5));

  Interest interest5("/interest4");
  keyChain.sign(interest5, SigningInfo(SigningInfo::SIGNER_TYPE_SHA256));
  BOOST_CHECK(verifySha256Digest(interest5));

  // SigningInfo is set to Identity
  Data data6("/data6");
  SigningInfo info6;
  info6.setPibIdentity(id);
  keyChain.sign(data6, info6);
  BOOST_CHECK_EQUAL(data6.getSignature().getKeyLocator().getName(),
                    id.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(data6, id.getDefaultKey().getPublicKey()));

  Interest interest6("/interest6");
  keyChain.sign(interest6, info6);
  SignatureInfo sigInfo6(interest6.getName()[-2].blockFromValue());
  BOOST_CHECK_EQUAL(sigInfo6.getKeyLocator().getName(),
                    id.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(interest6, id.getDefaultKey().getPublicKey()));

  // SigningInfo is set to Identity
  Data data7("/data7");
  SigningInfo info7;
  info7.setPibKey(id.getDefaultKey());
  keyChain.sign(data7, info7);
  BOOST_CHECK_EQUAL(data7.getSignature().getKeyLocator().getName(),
                    id.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(data7, id.getDefaultKey().getPublicKey()));

  Interest interest7("/interest7");
  keyChain.sign(interest7, info7);
  SignatureInfo sigInfo7(interest7.getName()[-2].blockFromValue());
  BOOST_CHECK_EQUAL(sigInfo7.getKeyLocator().getName(),
                    id.getDefaultKey().getDefaultCertificate().getName().getPrefix(-1));
  BOOST_CHECK(verifySignature(interest7, id.getDefaultKey().getPublicKey()));
}

BOOST_AUTO_TEST_CASE(Cert)
{
  KeyChain keyChain("pib-memory:", "tpm-memory:");
  Name idName("/id");
  Identity id = keyChain.createIdentity(idName);

  Data cert = id.getDefaultKey().getDefaultCertificate();

  BOOST_CHECK(isCertName(cert.getName()));
  BOOST_CHECK_EQUAL(std::get<0>(parseKeyName(toKeyName(cert.getName()))), idName);
  BOOST_CHECK_NO_THROW(SignatureInfo(cert.getSignature().getInfo()).getValidityPeriod());
}

BOOST_AUTO_TEST_SUITE_END() // TestKeyChain

BOOST_AUTO_TEST_SUITE_END() // Tmp

BOOST_AUTO_TEST_SUITE_END() // Security

} // namespace tests
} // namespace tmp
} // namespace security
} // namespace ndn
