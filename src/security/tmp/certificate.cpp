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
const ssize_t Certificate::ISSUER_ID_OFFSET = -2;
const ssize_t Certificate::KEY_COMPONENT_OFFSET = -3;
const ssize_t Certificate::KEY_ID_OFFSET = -4;
const size_t Certificate::MIN_CERT_NAME_LENGTH = 4;
const size_t Certificate::MIN_KEY_NAME_LENGTH = 2;
const name::Component Certificate::KEY_COMPONENT("KEY");

Certificate::Certificate()
{
  setContentType(tlv::ContentTypeValue::ContentType_Key);
}

Certificate::Certificate(Data&& data)
  : Data(data)
{
  if (!isCertName(getName())) {
    BOOST_THROW_EXCEPTION(Data::Error("Name does not follow certificate format naming convention"));
  }
  if (getContentType() != tlv::ContentTypeValue::ContentType_Key) {
    BOOST_THROW_EXCEPTION(Data::Error("ContentType is not KEY"));
  }
}

Certificate::Certificate(const Block& block)
  : Data(block)
{
  if (!isCertName(getName())) {
    BOOST_THROW_EXCEPTION(Data::Error("Name does not follow certificate format naming convention"));
  }
  if (getContentType() != tlv::ContentTypeValue::ContentType_Key) {
    BOOST_THROW_EXCEPTION(Data::Error("ContentType is not KEY"));
  }
}

Name
Certificate::getKeyName() const
{
  return getName().getPrefix(KEY_COMPONENT_OFFSET + 1);
}

Name
Certificate::getIdentity() const
{
  return getName().getPrefix(KEY_ID_OFFSET);
}

name::Component
Certificate::getKeyId() const
{
  return getName().get(KEY_ID_OFFSET);
}

name::Component
Certificate::getIssuerId() const
{
  return getName().get(ISSUER_ID_OFFSET);
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

bool
isCertName(const Name& certName)
{
  // [subject-name]/[key-id]/KEY/[issuer-id]/[version]
  return (certName.size() > tmp::Certificate::MIN_CERT_NAME_LENGTH &&
          certName.get(tmp::Certificate::KEY_COMPONENT_OFFSET) == tmp::Certificate::KEY_COMPONENT);
}

bool
isKeyName(const Name& keyName)
{
  // [subject-name]/[key-id]/KEY
  return (keyName.size() > tmp::Certificate::MIN_KEY_NAME_LENGTH &&
          keyName.get(-1) == tmp::Certificate::KEY_COMPONENT);
}

Name
toKeyName(const Name& certName)
{
  if (!isCertName(certName))
    BOOST_THROW_EXCEPTION(std::invalid_argument("wrong cert name"));

  return certName.getPrefix(tmp::Certificate::KEY_COMPONENT_OFFSET + 1); // trim issuer-id and version
}

std::tuple<Name, name::Component>
parseKeyName(const Name& keyName)
{
  if (!isKeyName(keyName))
    BOOST_THROW_EXCEPTION(std::invalid_argument("wrong key name"));

  // parse identity & key-id from "/.../[key-id]/KEY"
  return std::make_tuple(keyName.getPrefix(-2), keyName.get(-2));
}

} // namespace security
} // namespace ndn
