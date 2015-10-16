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

#include "security/transform/stream-source.hpp"
#include "security/transform/stream-sink.hpp"

#include "boost-test.hpp"

namespace ndn {
namespace security {
namespace transform {
namespace tests {

BOOST_AUTO_TEST_SUITE(Security)

BOOST_AUTO_TEST_SUITE(TransformStreamSource)

BOOST_AUTO_TEST_CASE(Basic)
{
  std::string input =
    "0123456701234567012345670123456701234567012345670123456701234567"
    "01234567012345670123456701234567 1234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567"
    "0123456701234567012345670123456701234567012345670123456701234567";

  std::stringstream is(input);
  std::stringstream os;
  streamSource(is) >> streamSink(os);
  std::string output = os.str();

  BOOST_CHECK_EQUAL(input, output);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace transform
} // namespace security
} // namespace ndn
