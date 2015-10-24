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

#ifndef NDN_SECURITY_DETAIL_TRUST_ANCHOR_CONTAINER_HPP
#define NDN_SECURITY_DETAIL_TRUST_ANCHOR_CONTAINER_HPP

#include "trust-anchor-group.hpp"
#include "../../interest.hpp"
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <map>

namespace ndn {
namespace security {
namespace detail {

namespace mi = boost::multi_index;

/** @brief represents a container for trust anchors.
 *
 *  There are two kinds of anchors: static anchors exist permanently; dynamic anchors should be
 *  refreshed every period of time. Trust anchors can be grouped by group id. Id is unique for
 *  each group. There is a default group for anchors without id. All anchors inside the default
 *  group are static. For dynamic anchors, there must be group id, cert path and refresh period.
 */
class TrustAnchorContainer : noncopyable
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

  /** @brief Index for trust anchor group, has two indice: expire time and group id.
   */
  typedef mi::multi_index_container<
    TrustAnchorGroupPtr,
    mi::indexed_by<
      mi::ordered_non_unique<
        mi::const_mem_fun<TrustAnchorGroup, const time::system_clock::TimePoint&,
                          &TrustAnchorGroup::getExpireTime>
      >,

      mi::hashed_unique<
        mi::const_mem_fun<TrustAnchorGroup, const std::string&, &TrustAnchorGroup::getGroupId>
      >
    >
  > AnchorIndex;

  typedef AnchorIndex::nth_index<0>::type AnchorIndexByTime;
  typedef AnchorIndex::nth_index<1>::type AnchorIndexById;

  TrustAnchorContainer();

  ~TrustAnchorContainer();

  /**
   * @brief Insert a static trust anchor from data packet.
   *
   * @param cert     the certificate packet, must not be nullptr.
   * @param groupId  Certificate group id.
   *
   * @throw std::invalid_argument when cert is nullptr
   * @throw Error when @p groupId is duplicate.
   */
  void
  insert(shared_ptr<const Data> cert, const std::string& groupId = "");

  /**
   * @brief Insert dynamic trust anchors from path.
   *
   * @param groupId          Certificate group id, must not be empty.
   * @param certfilePath     Specifies the path to load the trust anchors.
   * @param refreshPeriod    Refresh period for the trust anchors, must be positive.
   *                         Relevant trust anchors will only be updated when find and
   *                         findByGroupId are called.
   * @param isDir            Tells whether the path is a directory or a single file.
   *
   * @throw std::invalid_argument when @p groupId empty, or @p refreshPeriod is 0
   * @throw Error when @p groupId is duplicate.
   */
  void
  insert(const std::string& groupId, const std::string& certfilePath,
         const time::nanoseconds& refreshPeriod, bool isDir = false);

  /**
   * @brief Get certificate given key name
   *        The method will also refresh outdated trust anchor entries.
   *
   * @param keyName  Key name for searching the certificate.
   *
   * @return The found certificate, would be nullptr if not found.
   */
  shared_ptr<const Data>
  find(const Name& keyName);

  /**
   * @brief Find certificate given interest
   *        The method will also refresh outdated trust anchor entries.
   *
   * @param interest  The input interest packet.
   *
   * @return The found certificate according that matches the interest.
   *         Return nullptr if not found.
   *
   * @todo Child selector is not supported.
   *
   */
  shared_ptr<const Data>
  find(const Interest& interest);

  /**
   * @brief Get certificates under group id
   *        The method will also refresh outdated trust anchor entries.
   *
   * @param groupId  Id for trust anchor to help group trust anchors.
   *                 It can be used as rule id in trust schema.
   *                 All certificates with empty id belong to one group.
   *
   * @return certificate in the group; may be empty list
   */
  const std::list<shared_ptr<const Data>>
  findByGroupId(const std::string& groupId);

private:
  /**
   * @brief refresh anchors
   *
   * This is triggered by find and findByGroupId.
   */
  void
  refreshAnchors();

private:
  std::map<Name, shared_ptr<const Data>> m_anchors;
  AnchorIndex m_anchorIndex;
  AnchorIndexByTime& m_anchorIndexByTime;
  AnchorIndexById& m_anchorIndexById;
};

} // namespace detail
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_DETAIL_TRUST_ANCHOR_CONTAINER_HPP
