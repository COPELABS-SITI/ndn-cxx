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

#include "security/validator/certificate-cache.hpp"

#include "../../unit-test-time-fixture.hpp"
#include "boost-test.hpp"

namespace ndn {
namespace security {
namespace validator {
namespace tests {

using namespace ndn::tests;

BOOST_AUTO_TEST_SUITE(Security)
BOOST_AUTO_TEST_SUITE(Validator)
BOOST_AUTO_TEST_SUITE(TestCertificateCache)

BOOST_FIXTURE_TEST_CASE(Find, UnitTestTimeFixture)
{
  CertificateCache certCache(time::nanoseconds(time::seconds(10)));
  Name identity("/TestCertificateCache/Find/KEY");
  identity.appendVersion();
  shared_ptr<Data> cert;

  time::system_clock::TimePoint expireTime = time::system_clock::now() - time::seconds(10);

  // Empty cert
  BOOST_CHECK_THROW(certCache.insert(cert, expireTime), std::invalid_argument);

  cert = make_shared<Data>(identity);
  // Expire time is smaller than not.
  BOOST_CHECK_NO_THROW(certCache.insert(cert, expireTime));
  BOOST_CHECK(certCache.find(identity) == nullptr);

  // Expire in 10 seconds.
  expireTime += time::seconds(20);
  BOOST_CHECK_NO_THROW(certCache.insert(cert, expireTime));

  advanceClocks(time::milliseconds(5000), 1);
  // Find by name
  BOOST_CHECK(certCache.find(identity) != nullptr);

  advanceClocks(time::milliseconds(15000), 1);
  BOOST_CHECK(certCache.find(identity) == nullptr);
}

BOOST_FIXTURE_TEST_CASE(FindByInterest, UnitTestTimeFixture)
{
  CertificateCache certCache(time::nanoseconds(time::seconds(10)));
  Name identity("/TestCertificateCache/FindByInterest/KEY");
  identity.appendVersion();
  shared_ptr<Data> cert = make_shared<Data>(identity);

  time::system_clock::TimePoint expireTime = time::system_clock::now() + time::seconds(10);
  BOOST_CHECK_NO_THROW(certCache.insert(cert, expireTime));

  // Find by interest
  Interest interest1(identity);
  BOOST_CHECK(certCache.find(interest1) != nullptr);
  Interest interest2(identity.getPrefix(-1));
  BOOST_CHECK(certCache.find(interest2) != nullptr);
  Interest interest3(identity.appendVersion());
  BOOST_CHECK(certCache.find(interest3) == nullptr);

  advanceClocks(time::milliseconds(12000), 1);
  BOOST_CHECK(certCache.find(identity) == nullptr);

  Name identity3("/id/ksk-1/KEY/%00%00%00%01/%FD%01");
  auto cert3 = make_shared<Data>(identity3);
  Name identity4("/id/ksk-1/KEY/%00%00%00%02/%FD%01");
  auto cert4 = make_shared<Data>(identity4);
  Name identity5("/id/ksk-1/KEY/%00%00%00%03/%FD%01");
  auto cert5 = make_shared<Data>(identity5);
  expireTime += time::seconds(10);
  BOOST_REQUIRE_NO_THROW(certCache.insert(cert3, expireTime));
  BOOST_REQUIRE_NO_THROW(certCache.insert(cert4, expireTime));
  BOOST_REQUIRE_NO_THROW(certCache.insert(cert5, expireTime));

  advanceClocks(time::milliseconds(8000), 1);

  Interest interest4(identity3.getPrefix(-2));
  interest4.setExclude(Exclude().excludeOne(identity3.get(3)));
  BOOST_CHECK(certCache.find(interest4) != nullptr);
  BOOST_CHECK_EQUAL(certCache.find(interest4)->getName(), identity4);
}

BOOST_AUTO_TEST_SUITE_END() // TestCertificateCache
BOOST_AUTO_TEST_SUITE_END() // Validator
BOOST_AUTO_TEST_SUITE_END() // Security

} // namespace tests
} // namespace validator
} // namespace security
} // namespace ndn

