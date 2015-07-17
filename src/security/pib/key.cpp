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

#include "key.hpp"
#include "pib-impl.hpp"
#include "pib.hpp"
#include "../transform/public-key.hpp"

namespace ndn {
namespace security {
namespace pib {

using tmp::Certificate;

Key::Key()
  : m_keyType(KeyType::NONE)
  , m_hasDefaultCertificate(false)
  , m_needRefreshCerts(false)
  , m_impl(nullptr)
{
}

Key::Key(const Name& keyName, const uint8_t* key, size_t keyLen, shared_ptr<PibImpl> impl)
  : m_keyName(keyName)
  , m_key(key, keyLen)
  , m_hasDefaultCertificate(false)
  , m_needRefreshCerts(true)
  , m_impl(impl)
{
  validityCheck();

  std::tie(m_id, m_keyId) = parseKeyName(keyName);

  m_impl->addIdentity(m_id);
  m_impl->addKey(m_id, m_keyName, key, keyLen);

  transform::PublicKey publicKey;
  publicKey.loadPkcs8(key, keyLen);
  m_keyType = publicKey.getKeyType();
}

Key::Key(const Name& keyName, shared_ptr<PibImpl> impl)
  : m_keyName(keyName)
  , m_hasDefaultCertificate(false)
  , m_needRefreshCerts(true)
  , m_impl(impl)
{
  validityCheck();

  std::tie(m_id, m_keyId) = parseKeyName(keyName);

  m_key = m_impl->getKeyBits(m_keyName);

  transform::PublicKey key;
  key.loadPkcs8(m_key.buf(), m_key.size());
  m_keyType = key.getKeyType();
}

const Name&
Key::getName() const
{
  validityCheck();

  return m_keyName;
}

const Name&
Key::getIdentity() const
{
  validityCheck();

  return m_id;
}

const name::Component&
Key::getKeyId() const
{
  validityCheck();

  return m_keyId;
}

const Buffer&
Key::getPublicKey() const
{
  validityCheck();

  return m_key;
}

void
Key::addCertificate(const Certificate& certificate)
{
  validityCheck();

  if (certificate.getKeyName() != m_keyName)
    BOOST_THROW_EXCEPTION(Pib::Error("Certificate name does not match key name"));

  if (!m_needRefreshCerts &&
      m_certificates.find(certificate.getName()) == m_certificates.end()) {
    // if we have already loaded all the certificate, but the new certificate is not one of them
    // the CertificateContainer should be refreshed
    m_needRefreshCerts = true;
  }

  m_impl->addCertificate(certificate);
}

void
Key::removeCertificate(const Name& certName)
{
  validityCheck();

  if (m_hasDefaultCertificate && m_defaultCertificate.getName() == certName)
    m_hasDefaultCertificate = false;

  m_impl->removeCertificate(certName);
  m_needRefreshCerts = true;
}

Certificate
Key::getCertificate(const Name& certName) const
{
  validityCheck();

  return m_impl->getCertificate(certName);
}

const CertificateContainer&
Key::getCertificates() const
{
  validityCheck();

  if (m_needRefreshCerts) {
    m_certificates = std::move(CertificateContainer(m_impl->getCertificatesOfKey(m_keyName), m_impl));
    m_needRefreshCerts = false;
  }

  return m_certificates;
}

const Certificate&
Key::setDefaultCertificate(const Name& certName)
{
  validityCheck();

  m_defaultCertificate = m_impl->getCertificate(certName);
  m_impl->setDefaultCertificateOfKey(m_keyName, certName);
  m_hasDefaultCertificate = true;
  return m_defaultCertificate;
}

const Certificate&
Key::setDefaultCertificate(const Certificate& certificate)
{
  addCertificate(certificate);
  return setDefaultCertificate(certificate.getName());
}

const Certificate&
Key::getDefaultCertificate() const
{
  validityCheck();

  if (!m_hasDefaultCertificate) {
    m_defaultCertificate = m_impl->getDefaultCertificateOfKey(m_keyName);
    m_hasDefaultCertificate = true;
  }

  return m_defaultCertificate;
}

Key::operator bool() const
{
  return !(this->operator!());
}

bool
Key::operator!() const
{
  return (m_impl == nullptr);
}

void
Key::validityCheck() const
{
  if (m_impl == nullptr)
    BOOST_THROW_EXCEPTION(std::domain_error("Invalid Key instance"));
}

} // namespace pib
} // namespace security
} // namespace ndn
