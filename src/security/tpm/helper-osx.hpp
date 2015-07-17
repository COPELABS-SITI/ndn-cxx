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

#ifndef NDN_SECURITY_TPM_HELPER_OSX_HPP
#define NDN_SECURITY_TPM_HELPER_OSX_HPP

#include "../../common.hpp"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#ifndef NDN_CXX_HAVE_OSX_SECURITY
#error "This file should not be compiled ..."
#endif

namespace ndn {
namespace security {
namespace tpm {

/**
 * @brief Helper class to wrap CoreFoundation object pointers
 *
 * The class is similar in spirit to shared_ptr, but uses CoreFoundation
 * mechanisms to retain/release object.
 *
 * Original implementation by Christopher Hunt and it was borrowed from
 * http://www.cocoabuilder.com/archive/cocoa/130776-auto-cfrelease-and.html
 */
template<class T>
class CFReleaser
{
public:
  //////////////////////////////
  // Construction/destruction //

  CFReleaser()
    : m_typeRef(0)
  {
  }

  CFReleaser(const T& typeRef)
    : m_typeRef(typeRef)
  {
  }

  CFReleaser(const CFReleaser& inReleaser)
    : m_typeRef(0)
  {
    retain(inReleaser.m_typeRef);
  }

  CFReleaser&
  operator=(const T& typeRef)
  {
    if (typeRef != m_typeRef) {
      release();
      m_typeRef = typeRef;
    }
    return *this;
  }

  CFReleaser&
  operator=(const CFReleaser& inReleaser)
  {
    retain(inReleaser.m_typeRef);
    return *this;
  }

  ~CFReleaser()
  {
    release();
  }

  ////////////
  // Access //

  const T&
  get() const
  {
    return m_typeRef;
  }

  T&
  get()
  {
    return m_typeRef;
  }

  ///////////////////
  // Miscellaneous //

  void
  retain(const T& typeRef)
  {
    if (typeRef != 0) {
      CFRetain(typeRef);
    }
    release();
    m_typeRef = typeRef;
  }

  void
  retain()
  {
    T typeRef = m_typeRef;
    m_typeRef = 0;
    retain(typeRef);
  }

  void release()
  {
    if (m_typeRef != 0) {
      CFRelease(m_typeRef);
      m_typeRef = 0;
    }
  };

private:
  T m_typeRef;
};

class KeyRefOsx : public CFReleaser<SecKeyRef>
{
public:

  KeyRefOsx();

  KeyRefOsx(const SecKeyRef& typeRef);
};


} // namespace tpm
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_TPM_HELPER_OSX_HPP
