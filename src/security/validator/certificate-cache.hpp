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

#ifndef NDN_SECURITY_VALIDATOR_CERTIFICATE_CACHE_HPP
#define NDN_SECURITY_VALIDATOR_CERTIFICATE_CACHE_HPP

#include "../../interest.hpp"
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>

namespace ndn {
namespace security {
namespace validator {

namespace mi = boost::multi_index;

/**
 * @brief Represents a container for verified certificates.
 *
 * There would be an expire time for each certificate. The expire time should
 * be no larger than the current time plus maximum lifetime. All outdated
 * certificates would be removed when refresh.
 */
class CertificateCache : noncopyable
{
public:
  /**
   * @brief Create an object for certificate cache.
   *
   * @param maxLifeTime the maximum time that certificates could live inside cache, would
   *        be 1 hour by default.
   */
  explicit
  CertificateCache(const time::nanoseconds& maxLifeTime = DEFAULT_LIFE_TIME);

  ~CertificateCache() = default;

  /**
   * @brief Insert certificate into cache.
   *
   * @param cert        the certificate packet, must not be nullptr.
   * @param expireTime  the expire time of the certificate.
   *
   * @throw std::invalid_argument when @p cert is nullptr
   */
  void
  insert(shared_ptr<const Data> cert, const time::system_clock::TimePoint& expireTime);

  /**
   * @brief Get certificate given key name
   *
   * @param keyName  Key name for searching the certificate.
   *
   * @return The found certificate, nullptr if not found.
   */
  shared_ptr<const Data>
  find(const Name& keyName);

  /**
   * @brief Find certificate given interest
   *
   * @param interest  The input interest packet.
   *
   * @return The found certificate that matches the interest, nullptr if not found.
   *
   * @todo Child selector is not supported.
   *
   */
  shared_ptr<const Data>
  find(const Interest& interest);

private:
  /**
   * @brief Represents a certificate. Each certificate will have an expire time.
   */
  class Entry
  {
  public:
    Entry(shared_ptr<const Data> cert, const time::system_clock::TimePoint& expireTime)
      : cert(cert)
      , expireTime(expireTime)
    {
      BOOST_ASSERT(cert != nullptr);
    }

    const Name&
    getCertName() const
    {
      return cert->getName();
    }

  public:
    shared_ptr<const Data> cert;
    time::system_clock::TimePoint expireTime;
  };

  /**
   * @brief Remove all outdated certificate entries.
   */
  void
  refresh();

public:
  static const time::nanoseconds DEFAULT_LIFE_TIME;

private:
  /** @brief Index for certificates, has two indice: expire time and name.
   */
  typedef mi::multi_index_container<
    Entry,
    mi::indexed_by<
      mi::ordered_non_unique<
        mi::member<Entry, const time::system_clock::TimePoint, &Entry::expireTime>
      >,

      mi::ordered_unique<
        mi::const_mem_fun<Entry, const Name&, &Entry::getCertName>
      >
    >
  > CertIndex;

  typedef CertIndex::nth_index<0>::type CertIndexByTime;
  typedef CertIndex::nth_index<1>::type CertIndexByName;
  CertIndex m_certs;
  CertIndexByTime& m_certsByTime;
  CertIndexByName& m_certsByName;
  time::nanoseconds m_maxLifeTime;
};

} // namespace validator
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_VALIDATOR_CERTIFICATE_CACHE_HPP
