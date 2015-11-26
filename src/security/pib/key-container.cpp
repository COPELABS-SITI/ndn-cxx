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

#include "key-container.hpp"
#include "pib-impl.hpp"
#include "detail/key-impl.hpp"

namespace ndn {
namespace security {
namespace pib {

static void
keyNameCheck(const Name& identity, const Name& keyName)
{
  Name id;
  name::Component keyId;
  try {
    std::tie(id, keyId) = parseKeyName(keyName);
  }
  catch (std::runtime_error&) {
    BOOST_THROW_EXCEPTION(std::invalid_argument("Invalid key name"));
  }

  if (id != identity)
    BOOST_THROW_EXCEPTION(std::invalid_argument("Identity name does not match key name"));
}

KeyContainer::const_iterator::const_iterator(std::set<Name>::const_iterator it,
                                             const KeyContainer& container)
  : m_it(it)
  , m_container(container)
{
}

Key
KeyContainer::const_iterator::operator*()
{
  return m_container.get(*m_it);
}

KeyContainer::const_iterator&
KeyContainer::const_iterator::operator++()
{
  ++m_it;
  return *this;
}

KeyContainer::const_iterator
KeyContainer::const_iterator::operator++(int)
{
  const_iterator it(*this);
  ++m_it;
  return it;
}

bool
KeyContainer::const_iterator::operator==(const const_iterator& other)
{
  return (m_container.m_impl == other.m_container.m_impl &&
          m_it == other.m_it);
}

bool
KeyContainer::const_iterator::operator!=(const const_iterator& other)
{
  return !(*this == other);
}

KeyContainer::KeyContainer(const Name& identity,
                           shared_ptr<PibImpl> impl)
  : m_identity(identity)
  , m_impl(impl)
{
  BOOST_ASSERT(impl != nullptr);
  m_keyNames = impl->getKeysOfIdentity(identity);
}

KeyContainer::const_iterator
KeyContainer::begin() const
{
  return const_iterator(m_keyNames.begin(), *this);
}

KeyContainer::const_iterator
KeyContainer::end() const
{
  return const_iterator(m_keyNames.end(), *this);
}

KeyContainer::const_iterator
KeyContainer::find(const Name& keyName) const
{
  return const_iterator(m_keyNames.find(keyName), *this);
}

size_t
KeyContainer::size() const
{
  return m_keyNames.size();
}

Key
KeyContainer::add(const uint8_t* key, size_t keyLen, const Name& keyName)
{
  keyNameCheck(m_identity, keyName);

  if (m_keyNames.count(keyName) == 0) {
    m_keyNames.insert(keyName);
    m_keys[keyName] = shared_ptr<detail::KeyImpl>(new detail::KeyImpl(keyName, key, keyLen, m_impl));
  }

  return get(keyName);
}

void
KeyContainer::remove(const Name& keyName)
{
  keyNameCheck(m_identity, keyName);

  m_keyNames.erase(keyName);
  m_keys.erase(keyName);
  m_impl->removeKey(keyName);
}

Key
KeyContainer::get(const Name& keyName) const
{
  shared_ptr<detail::KeyImpl> key;
  auto it = m_keys.find(keyName);

  if (it != m_keys.end()) {
    key = it->second;
  }
  else {
    keyNameCheck(m_identity, keyName);
    auto keyImpl = shared_ptr<detail::KeyImpl>(new detail::KeyImpl(keyName, m_impl));
    m_keys[keyName] = keyImpl;
  }

  return Key(key);
}

bool
KeyContainer::isConsistent() const
{
  return m_keyNames == m_impl->getKeysOfIdentity(m_identity);
}

} // namespace pib
} // namespace security
} // namespace ndn
