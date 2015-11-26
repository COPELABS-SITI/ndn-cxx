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

#ifndef NDN_SECURITY_PIB_IDENTITY_CONTAINER_HPP
#define NDN_SECURITY_PIB_IDENTITY_CONTAINER_HPP

#include <set>
#include <unordered_map>
#include "identity.hpp"

namespace ndn {
namespace security {
namespace pib {

class PibImpl;

namespace detail {
class IdentityImpl;
} // namespace detail

/**
 * @brief Container of identities of a Pib
 *
 * The container is used to search/enumerate identities of a Pib.
 * The container can be created only by Pib.
 */
class IdentityContainer : noncopyable
{
public:
  class const_iterator
  {
  public:
    friend class IdentityContainer;

  public:
    /**
     * @brief Dereference the iterator
     * @return The corresponding Identity
     */
    Identity
    operator*();

    const_iterator&
    operator++();

    const_iterator
    operator++(int);

    bool
    operator==(const const_iterator& other);

    bool
    operator!=(const const_iterator& other);

  private:
    const_iterator(std::set<Name>::const_iterator it, const IdentityContainer& container);

  private:
    std::set<Name>::const_iterator m_it;
    const IdentityContainer& m_container;
  };

  typedef const_iterator iterator;
  friend class Pib;

public:
  const_iterator
  begin() const;

  const_iterator
  end() const;

  const_iterator
  find(const Name& keyId) const;

  size_t
  size() const;

  /// @brief Add @p identity into the container
  Identity
  add(const Name& identityName);

  /// @brief Remove @p identity from the container
  void
  remove(const Name& identity);

  /**
   * @brief Get @p identity from the container
   * @throw Pib::Error if @p identity does not exist
   */
  Identity
  get(const Name& identity) const;

  /**
   * @brief Check if the container is consistent with the backend storage
   *
   * @note this method is heavyweight and should be used in debugging mode only.
   */
  bool
  isConsistent() const;

NDN_CXX_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  /**
   * @brief Create identity container
   * @param impl The PIB backend implementation.
   */
  explicit
  IdentityContainer(shared_ptr<PibImpl> pibImpl);

  const std::set<Name>&
  getIdentityNames() const
  {
    return m_identityNames;
  }

  const std::unordered_map<Name, shared_ptr<detail::IdentityImpl>>&
  getLoadedIdentities() const
  {
    return m_identities;
  }

private:
  std::set<Name> m_identityNames;
  /// @brief Set of loaded detail::IdentityImpl.
  mutable std::unordered_map<Name, shared_ptr<detail::IdentityImpl>> m_identities;

  shared_ptr<PibImpl> m_pibImpl;
};

} // namespace pib

using pib::IdentityContainer;

} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_PIB_IDENTITY_CONTAINER_HPP
