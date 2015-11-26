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

#include "key.hpp"
#include "detail/key-impl.hpp"

namespace ndn {
namespace security {
namespace pib {

using tmp::Certificate;

Key::Key() = default;

Key::Key(weak_ptr<detail::KeyImpl> impl)
  : m_impl(impl)
{
}

const Name&
Key::getName() const
{
  return lock()->getName();
}

const Name&
Key::getIdentity() const
{
  return lock()->getIdentity();
}

const name::Component&
Key::getKeyId() const
{
  return lock()->getKeyId();
}

KeyType
Key::getKeyType() const
{
  return lock()->getKeyType();
}

const Buffer&
Key::getPublicKey() const
{
  return lock()->getPublicKey();
}

void
Key::addCertificate(const Certificate& certificate)
{
  return lock()->addCertificate(certificate);
}

void
Key::removeCertificate(const Name& certName)
{
  return lock()->removeCertificate(certName);
}

Certificate
Key::getCertificate(const Name& certName) const
{
  return lock()->getCertificate(certName);
}

const CertificateContainer&
Key::getCertificates() const
{
  return lock()->getCertificates();
}

const Certificate&
Key::setDefaultCertificate(const Name& certName)
{
  return lock()->setDefaultCertificate(certName);
}

const tmp::Certificate&
Key::setDefaultCertificate(const tmp::Certificate& certificate)
{
  return lock()->setDefaultCertificate(certificate);
}

const Certificate&
Key::getDefaultCertificate() const
{
  return lock()->getDefaultCertificate();
}

Key::operator bool() const
{
  return !(this->operator!());
}

bool
Key::operator!() const
{
  return (m_impl.lock() == nullptr);
}

shared_ptr<detail::KeyImpl>
Key::lock() const
{
  auto impl = m_impl.lock();

  if (impl == nullptr)
    BOOST_THROW_EXCEPTION(std::domain_error("Invalid key instance"));

  return impl;
}

} // namespace pib
} // namespace security
} // namespace ndn
