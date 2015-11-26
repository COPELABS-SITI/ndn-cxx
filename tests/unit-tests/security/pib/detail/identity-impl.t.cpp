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

#include "security/pib/detail/identity-impl.hpp"
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
BOOST_AUTO_TEST_SUITE(TestIdentityImpl)

using security::Pib;

BOOST_FIXTURE_TEST_CASE(Basic, PibDataFixture)
{
  auto pibImpl = make_shared<pib::PibMemory>();
  IdentityImpl identity1(id1, pibImpl, true);

  BOOST_CHECK_EQUAL(identity1.getName(), id1);
}

BOOST_FIXTURE_TEST_CASE(KeyOperation, PibDataFixture)
{
  auto pibImpl = make_shared<pib::PibMemory>();
  IdentityImpl identity1(id1, pibImpl, true);
  BOOST_CHECK_NO_THROW(IdentityImpl(id1, pibImpl, false));

  // identity does not have any key
  BOOST_CHECK_EQUAL(identity1.getKeys().size(), 0);

  // get non-existing key, throw Pib::Error
  BOOST_CHECK_THROW(identity1.getKey(id1Key1Name), Pib::Error);
  // get default key, throw Pib::Error
  BOOST_CHECK_THROW(identity1.getDefaultKey(), Pib::Error);
  // set non-existing key as default key, throw Pib::Error
  BOOST_REQUIRE_THROW(identity1.setDefaultKey(id1Key1Name), Pib::Error);

  // add key
  identity1.addKey(id1Key1.buf(), id1Key1.size(), id1Key1Name);
  BOOST_CHECK_NO_THROW(identity1.getKey(id1Key1Name));

  // new key becomes default key when there is no default key
  BOOST_REQUIRE_NO_THROW(identity1.getDefaultKey());
  const Key& defaultKey0 = identity1.getDefaultKey();
  BOOST_CHECK_EQUAL(defaultKey0.getName(), id1Key1Name);
  BOOST_CHECK_EQUAL_COLLECTIONS(defaultKey0.getPublicKey().begin(),
                                defaultKey0.getPublicKey().end(),
                                id1Key1.begin(),
                                id1Key1.end());

  // remove key
  identity1.removeKey(id1Key1Name);
  BOOST_CHECK_THROW(identity1.getKey(id1Key1Name), Pib::Error);
  BOOST_CHECK_THROW(identity1.getDefaultKey(), Pib::Error);

  // set default key directly
  BOOST_REQUIRE_NO_THROW(identity1.setDefaultKey(id1Key1.buf(), id1Key1.size(), id1Key1Name));
  BOOST_REQUIRE_NO_THROW(identity1.getDefaultKey());
  BOOST_CHECK_NO_THROW(identity1.getKey(id1Key1Name));

  // check default key
  const Key& defaultKey1 = identity1.getDefaultKey();
  BOOST_CHECK_EQUAL(defaultKey1.getName(), id1Key1Name);
  BOOST_CHECK_EQUAL_COLLECTIONS(defaultKey1.getPublicKey().begin(),
                                defaultKey1.getPublicKey().end(),
                                id1Key1.begin(),
                                id1Key1.end());

  // add another key
  identity1.addKey(id1Key2.buf(), id1Key2.size(), id1Key2Name);
  BOOST_CHECK_EQUAL(identity1.getKeys().size(), 2);

  // set default key through name
  BOOST_REQUIRE_NO_THROW(identity1.setDefaultKey(id1Key2Name));
  BOOST_REQUIRE_NO_THROW(identity1.getDefaultKey());
  const Key& defaultKey2 = identity1.getDefaultKey();
  BOOST_CHECK_EQUAL(defaultKey2.getName(), id1Key2Name);
  BOOST_CHECK_EQUAL_COLLECTIONS(defaultKey2.getPublicKey().begin(),
                                defaultKey2.getPublicKey().end(),
                                id1Key2.begin(),
                                id1Key2.end());

  // remove key
  identity1.removeKey(id1Key1Name);
  BOOST_CHECK_THROW(identity1.getKey(id1Key1Name), Pib::Error);
  BOOST_CHECK_EQUAL(identity1.getKeys().size(), 1);

  // set default key directly again, change the default setting
  BOOST_REQUIRE_NO_THROW(identity1.setDefaultKey(id1Key1.buf(), id1Key1.size(), id1Key1Name));
  const Key& defaultKey3 = identity1.getDefaultKey();
  BOOST_CHECK_EQUAL(defaultKey3.getName(), id1Key1Name);
  BOOST_CHECK_EQUAL_COLLECTIONS(defaultKey3.getPublicKey().begin(),
                                defaultKey3.getPublicKey().end(),
                                id1Key1.begin(),
                                id1Key1.end());
  BOOST_CHECK_EQUAL(identity1.getKeys().size(), 2);

  // remove all keys
  identity1.removeKey(id1Key1Name);
  BOOST_CHECK_THROW(identity1.getKey(id1Key1Name), Pib::Error);
  BOOST_CHECK_EQUAL(identity1.getKeys().size(), 1);
  identity1.removeKey(id1Key2Name);
  BOOST_CHECK_THROW(identity1.getKey(id1Key2Name), Pib::Error);
  BOOST_CHECK_EQUAL(identity1.getKeys().size(), 0);
  BOOST_CHECK_THROW(identity1.getDefaultKey(), Pib::Error);
}

BOOST_FIXTURE_TEST_CASE(Errors, PibDataFixture)
{
  auto pibImpl = make_shared<pib::PibMemory>();

  BOOST_CHECK_THROW(IdentityImpl(id1, pibImpl, false), Pib::Error);
  IdentityImpl identity1(id1, pibImpl, true);

  identity1.addKey(id1Key1.buf(), id1Key1.size(), id1Key1Name);
  BOOST_CHECK_THROW(identity1.addKey(id1Key1.buf(), id1Key1.size(), id1Key1Name), Pib::Error);
  BOOST_CHECK_THROW(identity1.addKey(id2Key1.buf(), id2Key1.size(), id2Key1Name), std::invalid_argument);
  BOOST_CHECK_THROW(identity1.removeKey(id2Key1Name), std::invalid_argument);
  BOOST_CHECK_THROW(identity1.getKey(id2Key1Name), std::invalid_argument);
  BOOST_CHECK_THROW(identity1.setDefaultKey(id2Key1.buf(), id2Key1.size(), id2Key1Name), std::invalid_argument);
  BOOST_CHECK_THROW(identity1.setDefaultKey(id2Key1Name), std::invalid_argument);
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
