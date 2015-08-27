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

#include "util/random.hpp"

#include "boost-test.hpp"
#include <boost/mpl/vector.hpp>

#include <cmath>

namespace ndn {
namespace tests {

BOOST_AUTO_TEST_SUITE(UtilRandom)

class PseudoRandomWord32
{
public:
  static uint32_t
  generate()
  {
    return random::generateWord32();
  }
};

class PseudoRandomWord64
{
public:
  static uint64_t
  generate()
  {
    return random::generateWord64();
  }
};

class SecureRandomWord32
{
public:
  static uint32_t
  generate()
  {
    return random::generateSecureWord32();
  }
};

class SecureRandomWord64
{
public:
  static uint64_t
  generate()
  {
    return random::generateSecureWord64();
  }
};

typedef boost::mpl::vector<PseudoRandomWord32,
                           PseudoRandomWord64,
                           SecureRandomWord32,
                           SecureRandomWord64> RandomGenerators;


static double
getDeviation(const std::vector<uint32_t>& counts, size_t size)
{
  // Kolmogorov-Smirnov Goodness-of-Fit Test
  // http://www.itl.nist.gov/div898/handbook/eda/section3/eda35g.htm

  std::vector<double> edf(counts.size(), 0.0);
  double probability = 0.0;
  for (size_t i = 0; i < counts.size(); i++) {
    probability += 1.0 * counts[i] / size;
    edf[i] = probability;
  }

  double t = 0.0;
  for (size_t i = 0; i < counts.size(); i++) {
    t = std::max(t, std::abs(edf[i] - (i * 1.0 / counts.size())));
  }

  return t;
}


BOOST_AUTO_TEST_CASE_TEMPLATE(GoodnessOfFit, RandomGenerator, RandomGenerators)
{
  const size_t MAX_BINS = 32;
  const uint32_t MAX_ITERATIONS = 35;

  std::vector<uint32_t> counts(MAX_BINS, 0);

  for (uint32_t i = 0; i < MAX_ITERATIONS; i++) {
    counts[RandomGenerator::generate() % MAX_BINS]++;
  }

  // Check if it is uniform distribution with confidence 0.95
  // http://dlc.erieri.com/onlinetextbook/index.cfm?fuseaction=textbook.appendix&FileName=Table7
  BOOST_WARN_LE(getDeviation(counts, MAX_ITERATIONS), 0.230);
}

BOOST_AUTO_TEST_CASE(GenerateRandomBlob)
{
  // Kolmogorov-Smirnov Goodness-of-Fit Test
  // http://www.itl.nist.gov/div898/handbook/eda/section3/eda35g.htm

  uint8_t buf[1024] = {0};
  random::generateSecureBlob(buf, sizeof(buf));

  std::vector<uint32_t> counts(256, 0);

  for (size_t i = 0; i < sizeof(buf); i++) {
    counts[buf[i]]++;
  }

  // Check if it is uniform distribution with confidence 0.95
  // http://dlc.erieri.com/onlinetextbook/index.cfm?fuseaction=textbook.appendix&FileName=Table7
  BOOST_WARN_LE(getDeviation(counts, sizeof(buf)), 0.230);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndn
