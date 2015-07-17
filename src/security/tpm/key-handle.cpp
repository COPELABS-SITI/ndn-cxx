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

#include "key-handle.hpp"

namespace ndn {
namespace security {
namespace tpm {

static const name::Component KEY_COMPONENT("KEY");
static const size_t MIN_KEY_NAME_SIZE = 2; // /.../[keyId]/KEY
static const ssize_t KEY_ID_OFFSET = -2;
static const ssize_t KEY_COMPONENT_OFFSET = -1;

KeyHandle::~KeyHandle() = default;

ConstBufferPtr
KeyHandle::sign(DigestAlgorithm digestAlgorithm, const uint8_t* buf, size_t size) const
{
  return doSign(digestAlgorithm, buf, size);
}

ConstBufferPtr
KeyHandle::decrypt(const uint8_t* cipherText, size_t cipherTextLen) const
{
  return doDecrypt(cipherText, cipherTextLen);
}

ConstBufferPtr
KeyHandle::derivePublicKey() const
{
  return doDerivePublicKey();
}

void
KeyHandle::setKeyName(const Name& keyName)
{
  BOOST_ASSERT(keyName.size() >= MIN_KEY_NAME_SIZE);
  BOOST_ASSERT(keyName.get(KEY_COMPONENT_OFFSET) == KEY_COMPONENT);
  m_keyName = keyName;
}

Name
KeyHandle::getKeyName() const
{
  if (m_keyName.size() < MIN_KEY_NAME_SIZE) { // /.../[keyId]/KEY
    BOOST_THROW_EXCEPTION(Error("key name is not set"));
  }
  return m_keyName;
}

name::Component
KeyHandle::getKeyId() const
{
  if (m_keyName.size() < MIN_KEY_NAME_SIZE) { // /.../[keyId]/KEY
    BOOST_THROW_EXCEPTION(Error("key name is not set"));
  }
  return m_keyName.get(KEY_ID_OFFSET);
}

} // namespace tpm
} // namespace security
} // namespace ndn
