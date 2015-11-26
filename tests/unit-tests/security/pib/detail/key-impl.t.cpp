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

#include "security/pib/detail/key-impl.hpp"
#include "security/pib/pib.hpp"
#include "security/pib/pib-memory.hpp"
#include "../pib-data-fixture.hpp"

#include "boost-test.hpp"

namespace ndn {
namespace security {
namespace pib {
namespace detail {
namespace tests {

using tmp::Certificate;

BOOST_AUTO_TEST_SUITE(Security)
BOOST_AUTO_TEST_SUITE(Pib)
BOOST_AUTO_TEST_SUITE(Detail)
BOOST_AUTO_TEST_SUITE(TestKeyImpl)

using security::Pib;

BOOST_FIXTURE_TEST_CASE(Basic, PibDataFixture)
{
  auto pibImpl = make_shared<pib::PibMemory>();
  KeyImpl key11(id1Key1Name, id1Key1.buf(), id1Key1.size(), pibImpl);

  BOOST_CHECK_EQUAL(key11.getName(), id1Key1Name);
  BOOST_CHECK_EQUAL(key11.getIdentity(), id1);
  BOOST_CHECK_EQUAL(key11.getKeyId(), id1Key1Name.get(-2));
  BOOST_CHECK_EQUAL(key11.getKeyType(), KeyType::EC);
  BOOST_CHECK_EQUAL_COLLECTIONS(key11.getPublicKey().begin(), key11.getPublicKey().end(),
                                id1Key1.begin(), id1Key1.end());

  KeyImpl key11Bak(id1Key1Name, pibImpl);
  BOOST_CHECK_EQUAL(key11Bak.getName(), id1Key1Name);
  BOOST_CHECK_EQUAL(key11Bak.getIdentity(), id1);
  BOOST_CHECK_EQUAL(key11Bak.getKeyId(), id1Key1Name.get(-2));
  BOOST_CHECK_EQUAL(key11Bak.getKeyType(), KeyType::EC);
  BOOST_CHECK_EQUAL_COLLECTIONS(key11Bak.getPublicKey().begin(), key11Bak.getPublicKey().end(),
                                id1Key1.begin(), id1Key1.end());

}

BOOST_FIXTURE_TEST_CASE(CertificateOperation, PibDataFixture)
{
  auto pibImpl = make_shared<pib::PibMemory>();
  KeyImpl key11(id1Key1Name, id1Key1.buf(), id1Key1.size(), pibImpl);
  BOOST_CHECK_NO_THROW(KeyImpl(id1Key1Name, pibImpl));

  // key does not have any certificate
  BOOST_CHECK_EQUAL(key11.getCertificates().size(), 0);

  // get non-existing certificate, throw Pib::Error
  BOOST_CHECK_THROW(key11.getCertificate(id1Key1Cert1.getName()), Pib::Error);
  // get default certificate, throw Pib::Error
  BOOST_CHECK_THROW(key11.getDefaultCertificate(), Pib::Error);
  // set non-existing certificate as default certificate, throw Pib::Error
  BOOST_REQUIRE_THROW(key11.setDefaultCertificate(id1Key1Cert1.getName()), Pib::Error);

  // add certificate
  key11.addCertificate(id1Key1Cert1);
  BOOST_CHECK_NO_THROW(key11.getCertificate(id1Key1Cert1.getName()));

  // new certificate becomes default certificate when there is no default certificate
  BOOST_REQUIRE_NO_THROW(key11.getDefaultCertificate());
  const Certificate& defaultCert0 = key11.getDefaultCertificate();
  BOOST_CHECK_EQUAL(defaultCert0.getName(), id1Key1Cert1.getName());
  BOOST_CHECK_EQUAL_COLLECTIONS(defaultCert0.wireEncode().wire(),
                                defaultCert0.wireEncode().wire() + defaultCert0.wireEncode().size(),
                                id1Key1Cert1.wireEncode().wire(),
                                id1Key1Cert1.wireEncode().wire() + id1Key1Cert1.wireEncode().size());

  // remove certificate
  key11.removeCertificate(id1Key1Cert1.getName());
  BOOST_CHECK_THROW(key11.getCertificate(id1Key1Cert1.getName()), Pib::Error);
  BOOST_CHECK_THROW(key11.getDefaultCertificate(), Pib::Error);

  // set default certificate directly
  BOOST_REQUIRE_NO_THROW(key11.setDefaultCertificate(id1Key1Cert1));
  BOOST_REQUIRE_NO_THROW(key11.getDefaultCertificate());
  BOOST_CHECK_NO_THROW(key11.getCertificate(id1Key1Cert1.getName()));

  // check default cert
  const Certificate& defaultCert1 = key11.getDefaultCertificate();
  BOOST_CHECK_EQUAL(defaultCert1.getName(), id1Key1Cert1.getName());
  BOOST_CHECK_EQUAL_COLLECTIONS(defaultCert1.wireEncode().wire(),
                                defaultCert1.wireEncode().wire() + defaultCert1.wireEncode().size(),
                                id1Key1Cert1.wireEncode().wire(),
                                id1Key1Cert1.wireEncode().wire() + id1Key1Cert1.wireEncode().size());

  // add another certificate
  key11.addCertificate(id1Key1Cert2);
  BOOST_CHECK_EQUAL(key11.getCertificates().size(), 2);

  // set default certificate through name
  BOOST_REQUIRE_NO_THROW(key11.setDefaultCertificate(id1Key1Cert2.getName()));
  BOOST_REQUIRE_NO_THROW(key11.getDefaultCertificate());
  const Certificate& defaultCert2 = key11.getDefaultCertificate();
  BOOST_CHECK_EQUAL(defaultCert2.getName(), id1Key1Cert2.getName());
  BOOST_CHECK_EQUAL_COLLECTIONS(defaultCert2.wireEncode().wire(),
                                defaultCert2.wireEncode().wire() + defaultCert2.wireEncode().size(),
                                id1Key1Cert2.wireEncode().wire(),
                                id1Key1Cert2.wireEncode().wire() + id1Key1Cert2.wireEncode().size());

  // remove certificate
  key11.removeCertificate(id1Key1Cert1.getName());
  BOOST_CHECK_THROW(key11.getCertificate(id1Key1Cert1.getName()), Pib::Error);
  BOOST_CHECK_EQUAL(key11.getCertificates().size(), 1);

  // set default certificate directly again, change the default setting
  BOOST_REQUIRE_NO_THROW(key11.setDefaultCertificate(id1Key1Cert1));
  const Certificate& defaultCert3 = key11.getDefaultCertificate();
  BOOST_CHECK_EQUAL(defaultCert3.getName(), id1Key1Cert1.getName());
  BOOST_CHECK_EQUAL_COLLECTIONS(defaultCert3.wireEncode().wire(),
                                defaultCert3.wireEncode().wire() + defaultCert3.wireEncode().size(),
                                id1Key1Cert1.wireEncode().wire(),
                                id1Key1Cert1.wireEncode().wire() + id1Key1Cert1.wireEncode().size());
  BOOST_CHECK_EQUAL(key11.getCertificates().size(), 2);

  // remove all certificates
  key11.removeCertificate(id1Key1Cert1.getName());
  BOOST_CHECK_THROW(key11.getCertificate(id1Key1Cert1.getName()), Pib::Error);
  BOOST_CHECK_EQUAL(key11.getCertificates().size(), 1);
  key11.removeCertificate(id1Key1Cert2.getName());
  BOOST_CHECK_THROW(key11.getCertificate(id1Key1Cert2.getName()), Pib::Error);
  BOOST_CHECK_THROW(key11.getDefaultCertificate(), Pib::Error);
  BOOST_CHECK_EQUAL(key11.getCertificates().size(), 0);
}

BOOST_FIXTURE_TEST_CASE(Errors, PibDataFixture)
{
  auto pibImpl = make_shared<pib::PibMemory>();

  BOOST_CHECK_THROW(KeyImpl(id1Key1Name, pibImpl), Pib::Error);
  KeyImpl key11(id1Key1Name, id1Key1.buf(), id1Key1.size(), pibImpl);
  BOOST_CHECK_THROW(KeyImpl(id1Key1Name, id1Key1.buf(), id1Key1.size(), pibImpl), Pib::Error);

  BOOST_CHECK_THROW(KeyImpl(Name("/wrong"), pibImpl), std::invalid_argument);
  BOOST_CHECK_THROW(KeyImpl(Name("/wrong"), id1Key1.buf(), id1Key1.size(), pibImpl), std::invalid_argument);
  Buffer wrongKey;
  BOOST_CHECK_THROW(KeyImpl(id1Key2Name, wrongKey.buf(), wrongKey.size(), pibImpl), std::invalid_argument);

  key11.addCertificate(id1Key1Cert1);
  BOOST_CHECK_THROW(key11.addCertificate(id1Key1Cert1), Pib::Error);
  BOOST_CHECK_THROW(key11.addCertificate(id1Key2Cert1), std::invalid_argument);
  BOOST_CHECK_THROW(key11.removeCertificate(id1Key2Cert1.getName()), std::invalid_argument);
  BOOST_CHECK_THROW(key11.getCertificate(id1Key2Cert1.getName()), std::invalid_argument);
  BOOST_CHECK_THROW(key11.setDefaultCertificate(id1Key2Cert1), std::invalid_argument);
  BOOST_CHECK_THROW(key11.setDefaultCertificate(id1Key2Cert1.getName()), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace detail
} // namespace pib
} // namespace security
} // namespace ndn
