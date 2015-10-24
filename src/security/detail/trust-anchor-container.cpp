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

#include "trust-anchor-container.hpp"

#include <boost/filesystem.hpp>

namespace ndn {
namespace security {
namespace detail {

TrustAnchorContainer::TrustAnchorContainer()
  : m_anchorIndexByTime(m_anchorIndex.get<0>())
  , m_anchorIndexById(m_anchorIndex.get<1>())
{
}

TrustAnchorContainer::~TrustAnchorContainer() = default;

void
TrustAnchorContainer::insert(shared_ptr<const Data> cert, const std::string& groupId)
{
  if (cert == nullptr)
    throw std::invalid_argument("Certificate should not be empty.");

  auto itr = m_anchorIndexById.find(groupId);
  if (itr != m_anchorIndexById.end()) {
    if (groupId == "") {
      (*itr)->loadAnchorFromData(cert);
    }
    else {
      throw Error("Group " + groupId + " already exists.");
    }
    return;
  }
  m_anchorIndexById.insert(make_shared<TrustAnchorGroup>(m_anchors, cert, groupId));
}

void
TrustAnchorContainer::insert(const std::string& groupId, const std::string& certfilePath,
                             const time::nanoseconds& refreshPeriod, bool isDir)
{
  if (groupId == "")
    throw std::invalid_argument("Group Id should not be empty for dynamic anchors");

  if (refreshPeriod <= time::nanoseconds(0))
    throw std::invalid_argument("Refresh Period should be larger than 0");

  if (m_anchorIndexById.count(groupId) > 0) {
    throw Error("Group " + groupId + " already exists.");
  }

  auto anchor = make_shared<TrustAnchorGroup>(m_anchors, groupId, certfilePath,
                                              refreshPeriod, isDir);
  m_anchorIndexById.insert(anchor);
}

shared_ptr<const Data>
TrustAnchorContainer::find(const Name& keyName)
{
  refreshAnchors();
  auto itr = m_anchors.lower_bound(keyName);
  if (itr == m_anchors.end())
    return nullptr;
  return itr->second;
}

shared_ptr<const Data>
TrustAnchorContainer::find(const Interest& interest)
{
  refreshAnchors();

  for (auto i = m_anchors.lower_bound(interest.getName());
       i != m_anchors.end() && interest.getName().isPrefixOf(i->first);
       ++i) {
    auto data = i->second;
    if (interest.matchesData(*data)) {
      return data;
    }
  }
  return nullptr;
}

const std::list<shared_ptr<const Data>>
TrustAnchorContainer::findByGroupId(const std::string& groupId)
{
  refreshAnchors();
  std::list<shared_ptr<const Data>> res;
  auto itr = m_anchorIndexById.find(groupId);
  if (itr == m_anchorIndexById.end())
    return res;

  const auto& certNames = (*itr)->getCertNames();
  for (const auto& certName : certNames) {
    auto anchor = m_anchors.find(certName);
    if (anchor != m_anchors.end())
      res.push_back(anchor->second);
  }
  return res;
}

void
TrustAnchorContainer::refreshAnchors()
{
  time::system_clock::TimePoint now = time::system_clock::now();

  auto cIt = m_anchorIndexByTime.begin();
  while (cIt != m_anchorIndexByTime.end() && (*cIt)->getExpireTime() < now) {
    shared_ptr<TrustAnchorGroup> ptr = (*cIt);
    m_anchorIndexByTime.erase(cIt);

    ptr->refresh();
    m_anchorIndexByTime.insert(ptr);

    cIt = m_anchorIndexByTime.begin();
  }
}

} // namespace detail
} // namespace security
} // namespace ndn
