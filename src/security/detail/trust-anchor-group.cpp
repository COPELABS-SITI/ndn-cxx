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

#include "trust-anchor-group.hpp"

#include "../../util/io.hpp"
#include <boost/filesystem.hpp>

namespace ndn {
namespace security {
namespace detail {

TrustAnchorGroup::TrustAnchorGroup(std::map<Name, shared_ptr<const Data>>& anchors,
                                   const std::string& groupId, const std::string& certfilePath,
                                   const time::nanoseconds& refreshPeriod, bool isDir)
  : m_anchors(anchors)
  , m_isDir(isDir)
  , m_isDynamic(true)
  , m_path(certfilePath)
  , m_groupId(groupId)
  , m_refreshPeriod(refreshPeriod)
{
  BOOST_ASSERT(refreshPeriod > time::nanoseconds(0));
  refresh();
}

TrustAnchorGroup::TrustAnchorGroup(std::map<Name, shared_ptr<const Data>>& anchors,
                                   shared_ptr<const Data> cert, const std::string& groupId)
  : m_anchors(anchors)
  , m_isDir(false)
  , m_isDynamic(false)
  , m_path("")
  , m_groupId(groupId)
  , m_refreshPeriod(time::nanoseconds(0))
{
  loadAnchorFromData(cert);
  m_expireTime = time::system_clock::TimePoint::max();
}

TrustAnchorGroup::~TrustAnchorGroup() = default;

void
TrustAnchorGroup::loadAnchorFromData(shared_ptr<const Data> cert)
{
  BOOST_ASSERT(cert != nullptr);
  BOOST_ASSERT(m_isDynamic != true);
  m_certNames.push_back(cert->getName());
  m_anchors[cert->getName()] = cert;
}

void
TrustAnchorGroup::refresh()
{
  if (!m_isDynamic)
    return;

  namespace fs = boost::filesystem;

  for (const auto& certName: m_certNames) {
    auto itr = m_anchors.find(certName);
    m_anchors.erase(itr);
  }

  m_certNames.clear();
  m_expireTime = time::system_clock::now() + m_refreshPeriod;

  if (!fs::exists(m_path))
    return;

  if (!m_isDir) {
    loadAnchorFromFile(m_path);
  }
  else {
    fs::path dirPath(m_path);
    fs::directory_iterator end;

    for (fs::directory_iterator it(dirPath); it != end; it++) {
      loadAnchorFromFile(it->path().string());
    }
  }
}

void
TrustAnchorGroup::loadAnchorFromFile(const std::string& path)
{
  shared_ptr<Data> cert = io::load<Data>(path);
  if (!static_cast<bool>(cert)) {
    return;
  }

  BOOST_ASSERT(cert->getName().size() >= 1);
  m_certNames.push_back(cert->getName());
  m_anchors[cert->getName()] = cert;
}

} // namespace detail
} // namespace security
} // namespace ndn
