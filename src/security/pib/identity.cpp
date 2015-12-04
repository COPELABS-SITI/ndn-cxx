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

#include "identity.hpp"
#include "pib-impl.hpp"
#include "pib.hpp"
#include "../transform.hpp"
#include "../../encoding/buffer-stream.hpp"

namespace ndn {
namespace security {
namespace pib {

static void
keyNameCheck(const Name& identity, const Name& keyName)
{
  Name id;
  name::Component keyId;
  std::tie(id, keyId) = parseKeyName(keyName);

  if (id != identity)
    BOOST_THROW_EXCEPTION(Pib::Error("Identity name does not match key name"));
}

Identity::Identity()
  : m_hasDefaultKey(false)
  , m_needRefreshKeys(false)
  , m_impl(nullptr)
{
}

Identity::Identity(const Name& identityName, shared_ptr<PibImpl> impl, bool needInit)
  : m_name(identityName)
  , m_hasDefaultKey(false)
  , m_needRefreshKeys(true)
  , m_impl(impl)
{
  validityCheck();

  if (needInit)
    m_impl->addIdentity(m_name);
  else if (!m_impl->hasIdentity(m_name))
    BOOST_THROW_EXCEPTION(Pib::Error("Identity: " + m_name.toUri() + " does not exist"));
}

const Name&
Identity::getName() const
{
  validityCheck();

  return m_name;
}

Key
Identity::addKey(const uint8_t* key, size_t keyLen, const Name& keyName)
{
  validityCheck();

  keyNameCheck(m_name, keyName);

  if (!m_needRefreshKeys && m_keys.find(keyName) == m_keys.end()) {
    // if we have already loaded all the keys, but the new key is not one of them
    // the KeyContainer should be refreshed
    m_needRefreshKeys = true;
  }

  return Key(keyName, key, keyLen, m_impl);
}

void
Identity::removeKey(const Name& keyName)
{
  validityCheck();

  keyNameCheck(m_name, keyName);

  if (m_hasDefaultKey && m_defaultKey.getName() == keyName)
    m_hasDefaultKey = false;

  m_impl->removeKey(keyName);
  m_needRefreshKeys = true;
}

Key
Identity::getKey(const Name& keyName) const
{
  validityCheck();

  keyNameCheck(m_name, keyName);

  return Key(keyName, m_impl);
}

const KeyContainer&
Identity::getKeys() const
{
  validityCheck();

  if (m_needRefreshKeys) {
    m_keys = KeyContainer(m_name, m_impl->getKeysOfIdentity(m_name), m_impl);
    m_needRefreshKeys = false;
  }

  return m_keys;
}

Key&
Identity::setDefaultKey(const Name& keyName)
{
  validityCheck();

  keyNameCheck(m_name, keyName);

  m_defaultKey = Key(keyName, m_impl);
  m_hasDefaultKey = true;

  m_impl->setDefaultKeyOfIdentity(m_name, keyName);
  return m_defaultKey;
}

Key&
Identity::setDefaultKey(const uint8_t* key, size_t keyLen, const Name& keyName)
{
  validityCheck();

  keyNameCheck(m_name, keyName);

  addKey(key, keyLen, keyName);
  return setDefaultKey(keyName);
}

Key&
Identity::getDefaultKey() const
{
  validityCheck();

  if (!m_hasDefaultKey) {
    m_defaultKey = Key(m_impl->getDefaultKeyOfIdentity(m_name), m_impl);
    m_hasDefaultKey = true;
  }

  return m_defaultKey;
}

Identity::operator bool() const
{
  return !(this->operator!());
}

bool
Identity::operator!() const
{
  return (m_impl == nullptr);
}

void
Identity::validityCheck() const
{
  if (m_impl == nullptr)
    BOOST_THROW_EXCEPTION(std::domain_error("Invalid Identity instance"));
}

} // namespace pib
} // namespace security
} // namespace ndn
