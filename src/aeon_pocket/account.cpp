// Copyright (c) 2014, AEON, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <fstream>

#include "include_base_utils.h"
#include "account.h"
#include "warnings.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/keccak.h"
}
#include "cryptonote_core/cryptonote_basic_impl.h"
#include "cryptonote_core/cryptonote_format_utils.h"
using namespace std;

DISABLE_VS_WARNINGS(4244 4345)

namespace aeon_pocket
{
  //-----------------------------------------------------------------
  account_base_ext::account_base_ext()
  {
    set_null();
  }
  //-----------------------------------------------------------------
  void account_base_ext::set_null()
  {
    m_keys = cryptonote::account_keys();
  }
  //-----------------------------------------------------------------
  crypto::secret_key account_base_ext::generate(const crypto::secret_key& recovery_key, bool recover, bool two_random)
  {
    crypto::secret_key first = generate_keys(m_keys.m_account_address.m_spend_public_key, m_keys.m_spend_secret_key, recovery_key, recover);

    // rng for generating second set of keys is hash of first rng.  means only one set of electrum-style words needed for recovery
    crypto::secret_key second;
    keccak((uint8_t *)&first, sizeof(crypto::secret_key), (uint8_t *)&second, sizeof(crypto::secret_key));

    generate_keys(m_keys.m_account_address.m_view_public_key, m_keys.m_view_secret_key, second, two_random ? false : true);

    struct tm timestamp;
    timestamp.tm_year = 2014 - 1900;  // year 2014
    timestamp.tm_mon = 6 - 1;  // month june
    timestamp.tm_mday = 8;  // 8th of june
    timestamp.tm_hour = 0;
    timestamp.tm_min = 0;
    timestamp.tm_sec = 0;

    if (recover)
    {
      m_creation_timestamp = mktime(&timestamp);
    }
    else
    {
      m_creation_timestamp = time(NULL);
    }
    return first;
  }
  //-----------------------------------------------------------------
  void account_base_ext::generate(cryptonote::account_public_address address, crypto::secret_key view_key) {
    m_keys.m_account_address = address;
    m_keys.m_view_secret_key = view_key;
  }
  //-----------------------------------------------------------------
  const cryptonote::account_keys& account_base_ext::get_keys() const
  {
    return m_keys;
  }
  //-----------------------------------------------------------------
  std::string account_base_ext::get_public_address_str()
  {
    //TODO: change this code into base 58
    return get_account_address_as_str(m_keys.m_account_address);
  }
  //-----------------------------------------------------------------
}
