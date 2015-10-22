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
#include "back-end.hpp"
#include "key-handle.hpp"
#include "tpm.hpp"
#include "../transform.hpp"
#include "../../encoding/buffer-stream.hpp"
#include "../../util/random.hpp"

namespace ndn {
namespace security {
namespace tpm {

BackEnd::~BackEnd() = default;

bool
BackEnd::hasKey(const Name& keyName) const
{
  return doHasKey(keyName);
}

unique_ptr<KeyHandle>
BackEnd::getKeyHandle(const Name& keyName) const
{
  return doGetKeyHandle(keyName);
}

unique_ptr<KeyHandle>
BackEnd::createKey(const Name& identity, const KeyParams& params)
{
  // key name checking
  switch (params.getKeyIdType()) {
    case KeyIdType::USER_SPECIFIED: { // keyId is pre-set.
      Name keyName = identity;
      keyName.append(params.getKeyId()).append("KEY");
      if (hasKey(keyName)) {
        BOOST_THROW_EXCEPTION(Tpm::Error("key already exists"));
      }
      break;
    }
    case KeyIdType::SHA256: {
      // we assume sha256 can guarantee the uniqueness of key name.
      break;
    }
    case KeyIdType::RANDOM: {
      Name keyName;
      do {
        keyName = identity;
        keyName.append(name::Component::fromNumber(random::generateSecureWord64())).append("KEY");
      } while (hasKey(keyName));

      const_cast<KeyParams&>(params).setKeyId(keyName.get(-2));
      break;
    }
    default: {
      BOOST_THROW_EXCEPTION(Error("Unsupported key id type"));
    }
  }

  return doCreateKey(identity, params);
}

void
BackEnd::deleteKey(const Name& keyName)
{
  doDeleteKey(keyName);
}

ConstBufferPtr
BackEnd::exportKey(const Name& keyName, const char* pw, size_t pwLen)
{
  if (!hasKey(keyName)) {
    BOOST_THROW_EXCEPTION(Error("key does not exist"));
  }
  return doExportKey(keyName, pw, pwLen);
}

void
BackEnd::importKey(const Name& keyName, const uint8_t* pkcs8, size_t pkcs8Len, const char* pw, size_t pwLen)
{
  if (hasKey(keyName)) {
    BOOST_THROW_EXCEPTION(Error("key already exists"));
  }
  doImportKey(keyName, pkcs8, pkcs8Len, pw, pwLen);
}

void
BackEnd::setKeyName(KeyHandle& keyHandle, const Name& identity, const KeyParams& params)
{
  Name keyName(identity);

  name::Component keyId;
  switch (params.getKeyIdType()) {
    case KeyIdType::USER_SPECIFIED:
      keyId = params.getKeyId();
      break;
    case KeyIdType::SHA256: {
      using namespace transform;

      OBufferStream os;
      bufferSource(*keyHandle.derivePublicKey()) >> digestFilter() >> streamSink(os);
      keyId = name::Component(os.buf());
      break;
    }
    case KeyIdType::RANDOM: {
      BOOST_ASSERT(!params.getKeyId().empty());
      keyId = params.getKeyId();
      break;
    }
    default: {
      BOOST_ASSERT(false);
    }
  }
  keyName.append(keyId).append("KEY");
  keyHandle.setKeyName(keyName);
}

} // namespace tpm
} // namespace security
} // namespace ndn
