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

#include "security/pib/key-container.hpp"
#include "security/pib/pib.hpp"
#include "security/pib/pib-memory.hpp"
#include "pib-data-fixture.hpp"

#include "boost-test.hpp"

namespace ndn {
namespace security {
namespace pib {
namespace tests {

BOOST_AUTO_TEST_SUITE(SecurityKeyContainer)

BOOST_FIXTURE_TEST_CASE(TestKeyContainer, PibDataFixture)
{
  auto pibImpl = make_shared<PibMemory>();
  Pib pib("pib-memory", "", pibImpl);

  Identity identity1 = pib.addIdentity(id1);

  Key key11 = identity1.addKey(id1Key1.buf(), id1Key1.size(), id1Key1Name);
  Key key12 = identity1.addKey(id1Key2.buf(), id1Key2.size(), id1Key2Name);

  KeyContainer container = identity1.getKeys();
  BOOST_CHECK_EQUAL(container.size(), 2);
  BOOST_CHECK(container.find(id1Key1Name) != container.end());
  BOOST_CHECK(container.find(id1Key2Name) != container.end());

  std::set<Name> keyNames;
  keyNames.insert(id1Key1Name);
  keyNames.insert(id1Key2Name);

  KeyContainer::const_iterator it = container.begin();
  std::set<Name>::const_iterator testIt = keyNames.begin();
  BOOST_CHECK_EQUAL((*it).getName(), *testIt);
  it++;
  testIt++;
  BOOST_CHECK_EQUAL((*it).getName(), *testIt);
  ++it;
  testIt++;
  BOOST_CHECK(it == container.end());

  size_t count = 0;
  testIt = keyNames.begin();
  for (const auto& key : container) {
    BOOST_CHECK_EQUAL(key.getIdentity(), id1);
    BOOST_CHECK_EQUAL(key.getName(), *testIt);
    testIt++;
    count++;
  }
  BOOST_CHECK_EQUAL(count, 2);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace pib
} // namespace security
} // namespace ndn
