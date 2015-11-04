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

#include "certificate-cache.hpp"

namespace ndn {
namespace security {
namespace validator {

const time::nanoseconds CertificateCache::DEFAULT_LIFE_TIME = time::seconds(3600);

CertificateCache::CertificateCache(const time::nanoseconds& maxLifeTime)
  : m_certsByTime(m_certs.get<0>())
  , m_certsByName(m_certs.get<1>())
  , m_maxLifeTime(maxLifeTime)
{
}

void
CertificateCache::insert(shared_ptr<const Data> cert,
                         const time::system_clock::TimePoint& expireTime)
{
  if (cert == nullptr)
    throw std::invalid_argument("Certificate should not be empty.");

  time::system_clock::TimePoint now = time::system_clock::now();
  if (expireTime < now)
    return;

  time::system_clock::TimePoint max_expireTime = now + m_maxLifeTime;
  m_certs.insert(Entry(cert, std::min(expireTime, max_expireTime)));
}

shared_ptr<const Data>
CertificateCache::find(const Name& keyName)
{
  refresh();
  auto itr = m_certsByName.lower_bound(keyName);
  if (itr == m_certsByName.end())
    return nullptr;
  return itr->cert;
}

shared_ptr<const Data>
CertificateCache::find(const Interest& interest)
{
  BOOST_ASSERT(interest.getChildSelector() < 0);
  refresh();

  for (auto i = m_certsByName.lower_bound(interest.getName());
       i != m_certsByName.end() && interest.getName().isPrefixOf(i->getCertName());
       ++i) {
    auto data = i->cert;
    if (interest.matchesData(*data)) {
      return data;
    }
  }
  return nullptr;
}

void
CertificateCache::refresh()
{
  time::system_clock::TimePoint now = time::system_clock::now();

  auto cIt = m_certsByTime.begin();
  while (cIt != m_certsByTime.end() && cIt->expireTime < now) {
    m_certsByTime.erase(cIt);
    cIt = m_certsByTime.begin();
  }
}

} // namespace validator
} // namespace security
} // namespace ndn
