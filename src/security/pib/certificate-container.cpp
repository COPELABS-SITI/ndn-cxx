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

#include "certificate-container.hpp"
#include "pib-impl.hpp"

namespace ndn {
namespace security {
namespace pib {

using tmp::Certificate;

CertificateContainer::const_iterator::const_iterator(std::set<Name>::const_iterator it,
                                                     const CertificateContainer& container)
  : m_it(it)
  , m_container(container)
{
}

Certificate
CertificateContainer::const_iterator::operator*()
{
  return m_container.get(*m_it);
}

CertificateContainer::const_iterator&
CertificateContainer::const_iterator::operator++()
{
  ++m_it;
  return *this;
}

CertificateContainer::const_iterator
CertificateContainer::const_iterator::operator++(int)
{
  const_iterator it(m_it, m_container);
  ++m_it;
  return it;
}

bool
CertificateContainer::const_iterator::operator==(const const_iterator& other)
{
  return (m_container.m_impl == other.m_container.m_impl &&
          m_it == other.m_it);
}

bool
CertificateContainer::const_iterator::operator!=(const const_iterator& other)
{
  return !(*this == other);
}

CertificateContainer::CertificateContainer(const Name& keyName, shared_ptr<PibImpl> impl)
  : m_keyName(keyName)
  , m_impl(impl)
{
  BOOST_ASSERT(impl != nullptr);
  m_certNames = impl->getCertificatesOfKey(keyName);
}

CertificateContainer::const_iterator
CertificateContainer::begin() const
{
  return const_iterator(m_certNames.begin(), *this);
}

CertificateContainer::const_iterator
CertificateContainer::end() const
{
  return const_iterator(m_certNames.end(), *this);
}

CertificateContainer::const_iterator
CertificateContainer::find(const Name& certName) const
{
  return const_iterator(m_certNames.find(certName), *this);
}

size_t
CertificateContainer::size() const
{
  return m_certNames.size();
}

void
CertificateContainer::add(const Certificate& certificate)
{
  if (m_keyName != certificate.getKeyName())
    BOOST_THROW_EXCEPTION(std::invalid_argument("certificate name does not match key name"));

  const Name& certName = certificate.getName();
  m_certNames.insert(certName);
  m_certs[certName] = certificate;
  m_impl->addCertificate(certificate);
}

void
CertificateContainer::remove(const Name& certName)
{
  if (!isCertName(certName) || m_keyName != toKeyName(certName))
    BOOST_THROW_EXCEPTION(std::invalid_argument("certificate name is invalid or does not match key name"));

  m_certNames.erase(certName);
  m_certs.erase(certName);
  m_impl->removeCertificate(certName);
}

Certificate
CertificateContainer::get(const Name& certName) const
{
  auto it = m_certs.find(certName);

  if (it != m_certs.end())
    return it->second;

  if (!isCertName(certName) || m_keyName != toKeyName(certName))
    BOOST_THROW_EXCEPTION(std::invalid_argument("certificate name is invalid or does not match key name"));

  m_certs[certName] = m_impl->getCertificate(certName);
  return m_certs[certName];
}

bool
CertificateContainer::isConsistent() const
{
  return m_certNames == m_impl->getCertificatesOfKey(m_keyName);
}

} // namespace pib
} // namespace security
} // namespace ndn
