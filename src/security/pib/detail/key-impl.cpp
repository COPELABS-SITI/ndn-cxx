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

#include "key-impl.hpp"
#include "../pib-impl.hpp"
#include "../pib.hpp"
#include "../../transform/public-key.hpp"

namespace ndn {
namespace security {
namespace pib {
namespace detail {

using tmp::Certificate;

KeyImpl::KeyImpl(const Name& keyName, const uint8_t* key, size_t keyLen, shared_ptr<PibImpl> impl)
  : m_keyName(keyName)
  , m_key(key, keyLen)
  , m_isDefaultCertificateLoaded(false)
  , m_certificates(keyName, impl)
  , m_impl(impl)
{
  BOOST_ASSERT(impl != nullptr);

  if (m_impl->hasKey(m_keyName))
    BOOST_THROW_EXCEPTION(Pib::Error("overwriting existing keys"));

  try {
    std::tie(m_id, m_keyId) = parseKeyName(keyName);
  }
  catch (std::runtime_error&) {
    BOOST_THROW_EXCEPTION(std::invalid_argument("invalid key name"));
  }

  transform::PublicKey publicKey;
  try {
    publicKey.loadPkcs8(key, keyLen);
  }
  catch (transform::PublicKey::Error&) {
    BOOST_THROW_EXCEPTION(std::invalid_argument("invalid key bits"));
  }
  m_keyType = publicKey.getKeyType();

  m_impl->addKey(m_id, m_keyName, key, keyLen);
}

KeyImpl::KeyImpl(const Name& keyName, shared_ptr<PibImpl> impl)
  : m_keyName(keyName)
  , m_isDefaultCertificateLoaded(false)
  , m_certificates(keyName, impl)
  , m_impl(impl)
{
  BOOST_ASSERT(impl != nullptr);

  try {
    std::tie(m_id, m_keyId) = parseKeyName(keyName);
  }
  catch (std::runtime_error&) {
    BOOST_THROW_EXCEPTION(std::invalid_argument("invalid key name"));
  }

  m_key = m_impl->getKeyBits(m_keyName);

  transform::PublicKey key;
  key.loadPkcs8(m_key.buf(), m_key.size());
  m_keyType = key.getKeyType();
}

void
KeyImpl::addCertificate(const Certificate& certificate)
{
  BOOST_ASSERT(m_certificates.isConsistent());

  if (m_certificates.find(certificate.getName()) != m_certificates.end())
    BOOST_THROW_EXCEPTION(Pib::Error("overwriting existing certificate"));

  m_certificates.add(certificate);
}

void
KeyImpl::removeCertificate(const Name& certName)
{
  BOOST_ASSERT(m_certificates.isConsistent());

  if (m_isDefaultCertificateLoaded && m_defaultCertificate.getName() == certName)
    m_isDefaultCertificateLoaded = false;

  m_certificates.remove(certName);
}

Certificate
KeyImpl::getCertificate(const Name& certName) const
{
  BOOST_ASSERT(m_certificates.isConsistent());

  return m_certificates.get(certName);
}

const CertificateContainer&
KeyImpl::getCertificates() const
{
  BOOST_ASSERT(m_certificates.isConsistent());

  return m_certificates;
}

const Certificate&
KeyImpl::setDefaultCertificate(const Name& certName)
{
  BOOST_ASSERT(m_certificates.isConsistent());

  m_defaultCertificate = m_certificates.get(certName);
  m_impl->setDefaultCertificateOfKey(m_keyName, certName);
  m_isDefaultCertificateLoaded = true;
  return m_defaultCertificate;
}

const Certificate&
KeyImpl::setDefaultCertificate(const tmp::Certificate& certificate)
{
  addCertificate(certificate);
  return setDefaultCertificate(certificate.getName());
}

const Certificate&
KeyImpl::getDefaultCertificate() const
{
  BOOST_ASSERT(m_certificates.isConsistent());

  if (!m_isDefaultCertificateLoaded) {
    m_defaultCertificate = m_impl->getDefaultCertificateOfKey(m_keyName);
    m_isDefaultCertificateLoaded = true;
  }

  BOOST_ASSERT(m_impl->getDefaultCertificateOfKey(m_keyName).wireEncode() == m_defaultCertificate.wireEncode());

  return m_defaultCertificate;
}


} // namespace detail
} // namespace pib
} // namespace security
} // namespace ndn
