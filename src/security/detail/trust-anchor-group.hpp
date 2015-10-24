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

#ifndef NDN_SECURITY_DETAIL_TRUST_ANCHOR_GROUP_HPP
#define NDN_SECURITY_DETAIL_TRUST_ANCHOR_GROUP_HPP

#include "../../data.hpp"

#include <list>

namespace ndn {
namespace security {
namespace detail {

/** @brief Represents a list of trust anchors under certain group id and path.
 *
 *  There are two kinds of anchors: static anchors exist permanently; dynamic anchors should be
 *  refreshed every period of time. Trust anchors can be grouped by group id. Id is unique for
 *  each group. There is a default group for anchors without id. All anchors inside the default
 *  group are static. For dynamic anchors, there must be group id, cert path and refresh period.
 */
class TrustAnchorGroup
{
public:
  /**
   * @brief Create a new object for dynamic trust anchors from @p groupId and @p certfilePath.
   *
   * This contructor would load all the certificates from @p certfilePath into |m_anchors|
   * and save names into |m_certNames|. It will update |m_expireTime| to be the expire time
   * which equals to current time + @p refreshPeriod.
   *
   * @param anchors         A container for all the trust anchors indexed by packet name.
   *                        |m_anchors| will be its reference.
   * @param isDir           Tells whether the path is a directory or a single file.
   * @param certfilePath    File path for trust anchor, could be directory or file. If it is a
   *                        directory, all the certificates under this it would be loaded into
   *                        |m_anchors|.
   * @param groupId         Certificate group id, must not be empty.
   * @param refreshPeriod   Refresh time for the anchors under @p certfilePath, must be positive.
   */
  TrustAnchorGroup(std::map<Name, shared_ptr<const Data>>& anchors,
                   const std::string& groupId, const std::string& certfilePath,
                   const time::nanoseconds& refreshPeriod, bool isDir = false);

  /**
   * @brief Create a new object for a static trust anchor given data packet and group id
   *        |m_expireTime| would be set to maximum timepoint of system clock.
   *
   * @param cert      Certificate packet, must not be nullptr
   * @param groupId   Certificate group id.
   */
  TrustAnchorGroup(std::map<Name, shared_ptr<const Data>>& anchors, shared_ptr<const Data> cert,
                   const std::string& groupId);

  ~TrustAnchorGroup();

  const std::list<Name>&
  getCertNames() const
  {
    return m_certNames;
  }

  const time::system_clock::TimePoint&
  getExpireTime() const
  {
    return m_expireTime;
  }

  const time::nanoseconds&
  getRefreshPeriod() const
  {
    return m_refreshPeriod;
  }

  const std::string&
  getGroupId() const
  {
    return m_groupId;
  }

  bool
  isDynamic() const
  {
    return m_isDynamic;
  }

  /**
   * @brief Load static anchor given data packet.
   *
   * @pre !isDynamic()
   *
   * @param cert Certificate packet, must not be nullptr
   */
  void
  loadAnchorFromData(shared_ptr<const Data> cert);

  /**
   * @brief Refresh anchors under |m_path|
   *
   * During refreshing, |m_certs| would be updated to the current existing certificate under
   * |m_path|. And all previous certificates in |m_anchors| under this path will also be updated.
   * And |m_expireTime| would be updated to current time + |m_refreshPeriod| as the expired time.
   */
  void
  refresh();

private:
  void
  loadAnchorFromFile(const std::string& path);

private:
  std::list<Name> m_certNames;
  std::map<Name, shared_ptr<const Data>>& m_anchors;
  bool m_isDir;
  bool m_isDynamic;
  std::string m_path;
  std::string m_groupId;
  time::nanoseconds m_refreshPeriod;
  time::system_clock::TimePoint m_expireTime;
};

typedef shared_ptr<TrustAnchorGroup> TrustAnchorGroupPtr;

} // namespace detail
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_DETAIL_TRUST_ANCHOR_GROUP_HPP

