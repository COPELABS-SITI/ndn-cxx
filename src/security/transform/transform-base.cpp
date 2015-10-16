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

#include "transform-base.hpp"

namespace ndn {
namespace security {
namespace transform {

Error::Error(size_t index, const std::string& what)
  : std::runtime_error("Error in module " + std::to_string(index) + ": " + what)
  , m_index(index)
{
}

Downstream::Downstream()
  : m_isEnd(false)
{
}

size_t
Downstream::write(const uint8_t* buf, size_t size)
{
  if (m_isEnd)
    throw Error(getIndex(), "Module is closed, no more input");

  size_t nBytesWritten = doWrite(buf, size);
  BOOST_ASSERT(nBytesWritten <= size);
  return nBytesWritten;
}

void
Downstream::end()
{
  if (m_isEnd)
    return;

  m_isEnd = true;
  return doEnd();
}

Upstream::Upstream()
  : m_next(nullptr)
{
}

void
Upstream::appendChain(unique_ptr<Downstream> tail)
{
  if (m_next == nullptr) {
    m_next = std::move(tail);
  }
  else {
    BOOST_ASSERT(dynamic_cast<Transform*>(m_next.get()) != nullptr);
    static_cast<Transform*>(m_next.get())->appendChain(std::move(tail));
  }
}

Source::Source()
  : m_nModules(1) // source per se is counted as one module
{
}

void
Source::pump()
{
  doPump();
}

Source&
Source::operator>>(unique_ptr<Transform> transform)
{
  transform->setIndex(m_nModules);
  m_nModules++;
  this->appendChain(std::move(transform));

  return *this;
}

void
Source::operator>>(unique_ptr<Sink> sink)
{
  sink->setIndex(m_nModules);
  m_nModules++;
  this->appendChain(std::move(sink));

  this->pump();
}

} // namespace transform
} // namespace security
} // namespace ndn
