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

#include "security/detail/trust-anchor-container.hpp"

#include "../../unit-test-time-fixture.hpp"
#include "util/io.hpp"
#include "boost-test.hpp"
#include <boost/filesystem.hpp>

namespace ndn {
namespace security {
namespace detail {
namespace tests {

using namespace ndn::tests;

BOOST_AUTO_TEST_SUITE(Security)
BOOST_AUTO_TEST_SUITE(Detail)
BOOST_AUTO_TEST_SUITE(TestTrustAnchorContainer)

const uint8_t sigInfo[] = {
0x16, 0x1b, // SignatureInfo
  0x1b, 0x01, // SignatureType
    0x03,
  0x1c, 0x16, // KeyLocator
    0x07, 0x14, // Name
      0x08, 0x04,
        0x74, 0x65, 0x73, 0x74,
      0x08, 0x03,
        0x6b, 0x65, 0x79,
      0x08, 0x07,
        0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72
};

const uint8_t sigValue[] = {
0x17, 0x40, // SignatureValue
  0x2f, 0xd6, 0xf1, 0x6e, 0x80, 0x6f, 0x10, 0xbe, 0xb1, 0x6f, 0x3e, 0x31, 0xec,
  0xe3, 0xb9, 0xea, 0x83, 0x30, 0x40, 0x03, 0xfc, 0xa0, 0x13, 0xd9, 0xb3, 0xc6,
  0x25, 0x16, 0x2d, 0xa6, 0x58, 0x41, 0x69, 0x62, 0x56, 0xd8, 0xb3, 0x6a, 0x38,
  0x76, 0x56, 0xea, 0x61, 0xb2, 0x32, 0x70, 0x1c, 0xb6, 0x4d, 0x10, 0x1d, 0xdc,
  0x92, 0x8e, 0x52, 0xa5, 0x8a, 0x1d, 0xd9, 0x96, 0x5e, 0xc0, 0x62, 0x0b
};

/** This fixture creates a directory and prepares two certificates.
    cert1 is written to a file under the directory, while cert2 is not.
 */
class AnchorContainerTestFixture : public UnitTestTimeFixture
{
public:
  AnchorContainerTestFixture()
  {
    boost::filesystem::create_directory(boost::filesystem::path(UNIT_TEST_CONFIG_PATH));

    certDirPath = boost::filesystem::path(UNIT_TEST_CONFIG_PATH) / std::string("test-cert-dir");
    boost::filesystem::create_directory(certDirPath);

    certPath1 = boost::filesystem::path(UNIT_TEST_CONFIG_PATH) /
      std::string("test-cert-dir") / std::string("trust-anchor-1.cert");

    certPath2 = boost::filesystem::path(UNIT_TEST_CONFIG_PATH) /
      std::string("test-cert-dir") / std::string("trust-anchor-2.cert");

    Block sigInfoBlock(sigInfo, sizeof(sigInfo));
    Block sigValueBlock(sigValue, sizeof(sigValue));

    Signature sig(sigInfoBlock, sigValueBlock);

    identity1 = Name("/TestAnchorContainer/First/KEY").appendVersion();
    cert1 = make_shared<Data>(identity1);
    cert1->setSignature(sig);
    io::save(*cert1, certPath1.string());

    identity2 = Name("/TestAnchorContainer/Second/KEY").appendVersion();
    cert2 = make_shared<Data>(identity2);
    cert2->setSignature(sig);
  }

  ~AnchorContainerTestFixture()
  {
    boost::filesystem::remove_all(UNIT_TEST_CONFIG_PATH);
  }

public:
  boost::filesystem::path certDirPath;
  boost::filesystem::path certPath1;
  boost::filesystem::path certPath2;

  Name identity1;
  Name identity2;

  shared_ptr<Data> cert1;
  shared_ptr<Data> cert2;
};

const time::nanoseconds refreshPeriod = time::nanoseconds(1);

BOOST_FIXTURE_TEST_CASE(InsertDuplicateGroupId, AnchorContainerTestFixture)
{
  TrustAnchorContainer anchorContainer;
  BOOST_REQUIRE_NO_THROW(anchorContainer.insert("test", certPath1.string(), refreshPeriod));
  BOOST_CHECK_THROW(anchorContainer.insert(cert2, "test"), TrustAnchorContainer::Error);
  BOOST_CHECK_THROW(anchorContainer.insert("test", certPath2.string(), refreshPeriod),
                    TrustAnchorContainer::Error);
}

BOOST_FIXTURE_TEST_CASE(FindByInterest, AnchorContainerTestFixture)
{
  TrustAnchorContainer anchorContainer;
  BOOST_REQUIRE_NO_THROW(anchorContainer.insert("test", certPath1.string(), refreshPeriod));
  Interest interest(identity1);
  BOOST_CHECK(anchorContainer.find(interest) != nullptr);
  Interest interest1(identity1.getPrefix(-1));
  BOOST_CHECK(anchorContainer.find(interest1) != nullptr);
  identity1.appendVersion();
  Interest interest2(identity1);
  BOOST_CHECK(anchorContainer.find(interest2) == nullptr);

  Name identity3("/id/ksk-1/KEY/%00%00%00%01/%FD%01");
  auto cert3 = make_shared<Data>(identity3);
  Name identity4("/id/ksk-1/KEY/%00%00%00%02/%FD%01");
  auto cert4 = make_shared<Data>(identity4);
  Name identity5("/id/ksk-1/KEY/%00%00%00%03/%FD%01");
  auto cert5 = make_shared<Data>(identity5);
  BOOST_REQUIRE_NO_THROW(anchorContainer.insert(cert3, "exclude1"));
  BOOST_REQUIRE_NO_THROW(anchorContainer.insert(cert4, "exclude2"));
  BOOST_REQUIRE_NO_THROW(anchorContainer.insert(cert5, "exclude3"));
  Interest interest3(identity3.getPrefix(-2));
  interest3.setExclude(Exclude().excludeOne(identity3.get(3)));
  BOOST_CHECK(anchorContainer.find(interest3) != nullptr);
  BOOST_CHECK_EQUAL(anchorContainer.find(interest3)->getName(), identity4);
}

BOOST_FIXTURE_TEST_CASE(StaticAnchor, AnchorContainerTestFixture)
{
  TrustAnchorContainer anchorContainer;
  BOOST_REQUIRE_NO_THROW(anchorContainer.insert(cert1, "key"));
  BOOST_CHECK(anchorContainer.find(identity1) != nullptr);
  BOOST_CHECK_EQUAL(anchorContainer.findByGroupId("key").size(), 1);
}

BOOST_FIXTURE_TEST_CASE(DynamicAnchorFromFile, AnchorContainerTestFixture)
{
  TrustAnchorContainer anchorContainer;
  BOOST_REQUIRE_NO_THROW(anchorContainer.insert("test", certPath1.string(), refreshPeriod));

  advanceClocks(time::milliseconds(10), 200);

  BOOST_CHECK(anchorContainer.find(identity1) != nullptr);
  BOOST_CHECK_EQUAL(anchorContainer.findByGroupId("test").size(), 1);

  boost::filesystem::remove(certPath1);

  advanceClocks(time::milliseconds(10), 200);

  BOOST_CHECK(anchorContainer.find(identity1) == nullptr);
  BOOST_CHECK_EQUAL(anchorContainer.findByGroupId("test").size(), 0);
}

BOOST_FIXTURE_TEST_CASE(DynamicAnchorFromDir, AnchorContainerTestFixture)
{
  TrustAnchorContainer anchorContainer;

  BOOST_REQUIRE_NO_THROW(anchorContainer.insert("dir", certDirPath.string(),
                                                refreshPeriod, true /* isDir */));

  advanceClocks(time::milliseconds(10), 200);

  BOOST_CHECK(anchorContainer.find(identity1) != nullptr);
  BOOST_CHECK(anchorContainer.find(identity2) == nullptr);
  BOOST_CHECK_EQUAL(anchorContainer.findByGroupId("dir").size(), 1);

  io::save(*cert2, certPath2.string());

  advanceClocks(time::milliseconds(10), 200);

  BOOST_CHECK(anchorContainer.find(identity1) != nullptr);
  BOOST_CHECK(anchorContainer.find(identity2) != nullptr);
  BOOST_CHECK_EQUAL(anchorContainer.findByGroupId("dir").size(), 2);

  boost::filesystem::remove_all(certDirPath);

  advanceClocks(time::milliseconds(10), 200);

  BOOST_CHECK(anchorContainer.find(identity1) == nullptr);
  BOOST_CHECK_EQUAL(anchorContainer.findByGroupId("dir").size(), 0);
}


BOOST_AUTO_TEST_SUITE_END() // TestTrustAnchorContainer
BOOST_AUTO_TEST_SUITE_END() // Detail
BOOST_AUTO_TEST_SUITE_END() // Security

} // namespace tests
} // namespace detail
} // namespace security
} // namespace ndn
