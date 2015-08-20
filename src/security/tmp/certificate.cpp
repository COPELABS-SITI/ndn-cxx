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
 *
 * @author Zhiyi Zhang <dreamerbarrychang@gmail.com>
 * @author Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>
 */

#include "certificate.hpp"
#include "../../encoding/block-helpers.hpp"

namespace ndn {
namespace security {
namespace tmp {

BOOST_CONCEPT_ASSERT((WireEncodable<Certificate>));
BOOST_CONCEPT_ASSERT((WireDecodable<Certificate>));

const ssize_t Certificate::VERSION_OFFSET = -1;
const ssize_t Certificate::KEY_COMPONENT_OFFSET = -2;
const ssize_t Certificate::KEY_ID_OFFSET = -3;
const name::Component Certificate::KEY_COMPONENT("KEY");

Certificate::Certificate()
{
  setContentType(tlv::ContentTypeValue::ContentType_Key);
}

Certificate::Certificate(Data&& data)
  : Data(data)
{
  if (getName().at(KEY_COMPONENT_OFFSET) != KEY_COMPONENT) {
    BOOST_THROW_EXCEPTION(Data::Error("Name does not follow certificate format naming convention"));
  }
  if (getContentType() != tlv::ContentTypeValue::ContentType_Key) {
    BOOST_THROW_EXCEPTION(Data::Error("Type of content in block is not a key type"));
  }
}

Certificate::Certificate(const Block& block)
  : Data(block)
{
  if (getName().at(KEY_COMPONENT_OFFSET) != KEY_COMPONENT) {
    BOOST_THROW_EXCEPTION(Data::Error("Name does not follow certificate format naming convention"));
  }
  if (getContentType() != tlv::ContentTypeValue::ContentType_Key) {
    BOOST_THROW_EXCEPTION(Data::Error("Type of content in block is not a key type"));
  }
}

Name
Certificate::getKeyName() const
{
  return getName().getPrefix(VERSION_OFFSET);
}

Name
Certificate::getIdentity() const
{
  return getName().getPrefix(KEY_ID_OFFSET);
}

const Buffer
Certificate::getPublicKey() const
{
  if (getContent().empty())
    BOOST_THROW_EXCEPTION(Data::Error("There is a empty content"));
  return Buffer(getContent().value(), getContent().value_size());
}

bool
Certificate::isInValidityPeriod(const time::system_clock::TimePoint& ts) const
{
  return getSignature().getSignatureInfo().getValidityPeriod().isValid(ts);
}

const Name&
Certificate::getIssuerName() const
{
  return getSignature().getKeyLocator().getName();
}

const Block&
Certificate::getExtension(uint32_t type) const
{
  return getSignature().getSignatureInfo().getTypeSpecificTlv(type);
}

} // namespace tmp
} // namespace security
} // namespace ndn
