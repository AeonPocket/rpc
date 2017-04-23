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

#include <algorithm>
#include <boost/filesystem.hpp>
#include <unordered_set>
#include <vector>

#include "tx_pool.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_boost_serialization.h"
#include "cryptonote_config.h"
#include "blockchain_storage.h"
#include "common/boost_serialization_helper.h"
#include "common/int-util.h"
#include "misc_language.h"
#include "warnings.h"
#include "crypto/hash.h"

DISABLE_VS_WARNINGS(4244 4345 4503) //'boost::foreach_detail_::or_' : decorated name length exceeded, name was truncated

namespace cryptonote
{
  namespace
  {
    size_t const TRANSACTION_SIZE_LIMIT = (((CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE * 125) / 100) - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE);
  }

  //---------------------------------------------------------------------------------
  tx_memory_pool::tx_memory_pool(blockchain_storage& bchs): m_blockchain(bchs)
  {

  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_tx(const transaction &tx, /*const crypto::hash& tx_prefix_hash,*/ const crypto::hash &id, size_t blob_size, tx_verification_context& tvc, bool kept_by_block)
  {


    if(!check_inputs_types_supported(tx))
    {
      tvc.m_verifivation_failed = true;
      return false;
    }

    uint64_t inputs_amount = 0;
    if(!get_inputs_money_amount(tx, inputs_amount))
    {
      tvc.m_verifivation_failed = true;
      return false;
    }

    uint64_t outputs_amount = get_outs_money_amount(tx);

    if(outputs_amount >= inputs_amount)
    {
      LOG_PRINT_L0("transaction use more money then it has: use " << print_money(outputs_amount) << ", have " << print_money(inputs_amount));
      tvc.m_verifivation_failed = true;
      return false;
    }

    uint64_t fee = inputs_amount - outputs_amount;
    if (!kept_by_block && fee < MINIMUM_RELAY_FEE)
    {
      LOG_ERROR("transaction fee is not enough: " << print_money(fee) << ", minumim fee: " << print_money(DEFAULT_FEE));
      tvc.m_verifivation_failed = true;
      return false;
    }

    if (!kept_by_block && blob_size >= TRANSACTION_SIZE_LIMIT)
    {
      LOG_ERROR("transaction is too big: " << blob_size << " bytes, maximum size: " << TRANSACTION_SIZE_LIMIT);
      tvc.m_verifivation_failed = true;
      return false;
    }

    //check key images for transaction if it is not kept by block
    if(!kept_by_block)
    {
      if(have_tx_keyimges_as_spent(tx))
      {
        LOG_ERROR("Transaction with id= "<< id << " used already spent key images");
        tvc.m_verifivation_failed = true;
        return false;
      }
    }


    crypto::hash max_used_block_id = null_hash;
    uint64_t max_used_block_height = 0;
    bool ch_inp_res = m_blockchain.check_tx_inputs(tx, max_used_block_height, max_used_block_id);
    CRITICAL_REGION_LOCAL(m_transactions_lock);

    CHECK_AND_ASSERT_MES(id == get_transaction_hash(tx),false,"refusing to add tx with mismatched hash to pool");

    if(!ch_inp_res)
    {
      if(kept_by_block)
      {
        //anyway add this transaction to pool, because it related to block
        auto txd_p = m_transactions.insert(transactions_container::value_type(id, tx_details()));
        CHECK_AND_ASSERT_MES(txd_p.second, false, "transaction already exists at inserting in memory pool");
        txd_p.first->second.blob_size = blob_size;
        txd_p.first->second.tx = tx;
        txd_p.first->second.fee = inputs_amount - outputs_amount;
        txd_p.first->second.max_used_block_id = null_hash;
        txd_p.first->second.max_used_block_height = 0;
        txd_p.first->second.kept_by_block = kept_by_block;
        txd_p.first->second.receive_time = time(nullptr);
        tvc.m_verifivation_impossible = true;
        tvc.m_added_to_pool = true;
      }else
      {
        LOG_PRINT_L0("tx used wrong inputs, rejected");
        tvc.m_verifivation_failed = true;
        return false;
      }
    }else
    {
      //update transactions container
      auto txd_p = m_transactions.insert(transactions_container::value_type(id, tx_details()));
      CHECK_AND_ASSERT_MES(txd_p.second, false, "intrnal error: transaction already exists at inserting in memorypool");
      txd_p.first->second.blob_size = blob_size;
      txd_p.first->second.tx = tx;
      txd_p.first->second.kept_by_block = kept_by_block;
      txd_p.first->second.fee = inputs_amount - outputs_amount;
      txd_p.first->second.max_used_block_id = max_used_block_id;
      txd_p.first->second.max_used_block_height = max_used_block_height;
      txd_p.first->second.last_failed_height = 0;
      txd_p.first->second.last_failed_id = null_hash;
      txd_p.first->second.receive_time = time(nullptr);
      tvc.m_added_to_pool = true;

      if(txd_p.first->second.fee >= DEFAULT_FEE)
        tvc.m_should_be_relayed = true;
      else
      {
	LOG_PRINT_L1("not relaying, tx fee too low " << print_money(txd_p.first->second.fee) << "<" << print_money(DEFAULT_FEE) << " txid=" << id);
      }
    }

    tvc.m_verifivation_failed = true;
    //update image_keys container, here should everything goes ok.
    BOOST_FOREACH(const auto& in, tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, txin, false);
      std::unordered_set<crypto::hash>& kei_image_set = m_spent_key_images[txin.k_image];
      CHECK_AND_ASSERT_MES(kept_by_block || kei_image_set.size() == 0, false, "internal error: keeped_by_block=" << kept_by_block
                                          << ",  kei_image_set.size()=" << kei_image_set.size() << ENDL << "txin.k_image=" << txin.k_image << ENDL
                                          << "tx_id=" << id );
      auto ins_res = kei_image_set.insert(id);
      CHECK_AND_ASSERT_MES(ins_res.second, false, "internal error: try to insert duplicate iterator in key_image set");
    }

    tvc.m_verifivation_failed = false;
    //succeed
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_tx(const transaction &tx, tx_verification_context& tvc, bool keeped_by_block)
  {
    crypto::hash h = null_hash;
    size_t blob_size = 0;
    get_transaction_hash(tx, h, blob_size);
    return add_tx(tx, h, blob_size, tvc, keeped_by_block);
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::remove_transaction_keyimages(const transaction& tx)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    BOOST_FOREACH(const txin_v& vi, tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(vi, const txin_to_key, txin, false);
      auto it = m_spent_key_images.find(txin.k_image);
      CHECK_AND_ASSERT_MES(it != m_spent_key_images.end(), false, "failed to find transaction input in key images. img=" << txin.k_image << ENDL
                                    << "transaction id = " << get_transaction_hash(tx));
      std::unordered_set<crypto::hash>& key_image_set =  it->second;
      CHECK_AND_ASSERT_MES(key_image_set.size(), false, "empty key_image set, img=" << txin.k_image << ENDL
        << "transaction id = " << get_transaction_hash(tx));

      auto it_in_set = key_image_set.find(get_transaction_hash(tx));
      CHECK_AND_ASSERT_MES(it_in_set != key_image_set.end(), false, "transaction id not found in key_image set, img=" << txin.k_image << ENDL
        << "transaction id = " << get_transaction_hash(tx));
      key_image_set.erase(it_in_set);
      if(!key_image_set.size())
      {
        //it is now empty hash container for this key_image
        m_spent_key_images.erase(it);
      }

    }
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::take_tx(const crypto::hash &id, transaction &tx, size_t& blob_size, uint64_t& fee)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    auto it = m_transactions.find(id);
    if(it == m_transactions.end())
      return false;

    CHECK_AND_ASSERT_MES(id == get_transaction_hash(it->second.tx),false,"refusing to take tx with mismatched id");

    tx = it->second.tx;
    blob_size = it->second.blob_size;
    fee = it->second.fee;
    remove_transaction_keyimages(it->second.tx);
    m_transactions.erase(it);
    return true;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::on_idle()
  {
    m_remove_stuck_tx_interval.do_call([this](){return remove_stuck_transactions();});
  }
  //---------------------------------------------------------------------------------
  //proper tx_pool handling courtesy of CryptoZoidberg and Boolberry
  bool tx_memory_pool::remove_stuck_transactions()
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    for(auto it = m_transactions.begin(); it!= m_transactions.end();)
    {
      uint64_t tx_age = time(nullptr) - it->second.receive_time;

      if((tx_age > CRYPTONOTE_MEMPOOL_TX_LIVETIME && !it->second.kept_by_block) || 
         (tx_age > CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME && it->second.kept_by_block) )
      {
        LOG_PRINT_L0("Tx " << it->first << " removed from tx pool due to outdated, age: " << tx_age );
	remove_transaction_keyimages(it->second.tx);
	auto pit = it++;
        m_transactions.erase(pit);
      }else
        ++it;
    }
    return true;
  }
  //---------------------------------------------------------------------------------
  size_t tx_memory_pool::get_transactions_count() const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    return m_transactions.size();
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::get_transactions(std::list<transaction>& txs) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    BOOST_FOREACH(const auto& tx_vt, m_transactions)
      txs.push_back(tx_vt.second.tx);
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::get_transaction(const crypto::hash& id, transaction& tx) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    auto it = m_transactions.find(id);
    if(it == m_transactions.end())
      return false;
    tx = it->second.tx;
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::on_blockchain_inc(uint64_t new_block_height, const crypto::hash& top_block_id)
  {
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::on_blockchain_dec(uint64_t new_block_height, const crypto::hash& top_block_id)
  {
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx(const crypto::hash &id) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    if(m_transactions.count(id))
      return true;
    return false;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx_keyimges_as_spent(const transaction& tx) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    BOOST_FOREACH(const auto& in, tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, true);//should never fail
      if(have_tx_keyimg_as_spent(tokey_in.k_image))
         return true;
    }
    return false;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx_keyimg_as_spent(const crypto::key_image& key_im) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    return m_spent_key_images.end() != m_spent_key_images.find(key_im);
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::lock() const
  {
    m_transactions_lock.lock();
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::unlock() const
  {
    m_transactions_lock.unlock();
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::is_transaction_ready_to_go(tx_details& txd) const
  {
    //not the best implementation at this time, sorry :(
    //check is ring_signature already checked ?
    if(txd.max_used_block_id == null_hash)
    {//not checked, lets try to check

      if(txd.last_failed_id != null_hash && m_blockchain.get_current_blockchain_height() > txd.last_failed_height && txd.last_failed_id == m_blockchain.get_block_id_by_height(txd.last_failed_height))
        return false;//we already sure that this tx is broken for this height

      if(!m_blockchain.check_tx_inputs(txd.tx, txd.max_used_block_height, txd.max_used_block_id))
      {
        txd.last_failed_height = m_blockchain.get_current_blockchain_height()-1;
        txd.last_failed_id = m_blockchain.get_block_id_by_height(txd.last_failed_height);
        return false;
      }
    }else
    {
      if(txd.max_used_block_height >= m_blockchain.get_current_blockchain_height())
        return false;
      if(m_blockchain.get_block_id_by_height(txd.max_used_block_height) != txd.max_used_block_id)
      {
        //if we already failed on this height and id, skip actual ring signature check
        if(txd.last_failed_id == m_blockchain.get_block_id_by_height(txd.last_failed_height))
          return false;
        //check ring signature again, it is possible (with very small chance) that this transaction become again valid
        if(!m_blockchain.check_tx_inputs(txd.tx, txd.max_used_block_height, txd.max_used_block_id))
        {
          txd.last_failed_height = m_blockchain.get_current_blockchain_height()-1;
          txd.last_failed_id = m_blockchain.get_block_id_by_height(txd.last_failed_height);
          return false;
        }
      }
    }
    //if we here, transaction seems valid, but, anyway, check for key_images collisions with blockchain, just to be sure
    if(m_blockchain.have_tx_keyimges_as_spent(txd.tx))
      return false;

    //transaction is ok.
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_key_images(const std::unordered_set<crypto::key_image>& k_images, const transaction& tx)
  {
    for(size_t i = 0; i!= tx.vin.size(); i++)
    {
      CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_to_key, itk, false);
      if(k_images.count(itk.k_image))
        return true;
    }
    return false;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::append_key_images(std::unordered_set<crypto::key_image>& k_images, const transaction& tx)
  {
    for(size_t i = 0; i!= tx.vin.size(); i++)
    {
      CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_to_key, itk, false);
      auto i_res = k_images.insert(itk.k_image);
      CHECK_AND_ASSERT_MES(i_res.second, false, "internal error: key images pool cache - inserted duplicate image in set: " << itk.k_image);
    }
    return true;
  }
  //---------------------------------------------------------------------------------
  std::string tx_memory_pool::print_pool(bool short_format) const
  {
    std::stringstream ss;
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    for (const transactions_container::value_type& txe : m_transactions) {
      const tx_details& txd = txe.second;
      ss << "id: " << txe.first << std::endl;
      if (!short_format) {
        ss << obj_to_json_str(*const_cast<transaction*>(&txd.tx)) << std::endl;
      }
      ss << "blob_size: " << txd.blob_size << std::endl
        << "fee: " << print_money(txd.fee) << std::endl
        << "kept_by_block: " << (txd.kept_by_block ? 'T' : 'F') << std::endl
        << "max_used_block_height: " << txd.max_used_block_height << std::endl
        << "max_used_block_id: " << txd.max_used_block_id << std::endl
        << "last_failed_height: " << txd.last_failed_height << std::endl
        << "last_failed_id: " << txd.last_failed_id << std::endl;
    }

    return ss.str();
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::fill_block_template(block &bl, size_t median_size, uint64_t already_generated_coins, size_t &total_size, uint64_t &fee)
  {
    // Warning: This function takes already_generated_
    // coins as an argument and appears to do nothing
    // with it.

    CRITICAL_REGION_LOCAL(m_transactions_lock);

    total_size = 0;
    fee = 0;
    size_t n = 0;
    
    // Maximum block size is 130% of the median block size.  This gives a
    // little extra headroom for the max size transaction.
    size_t max_total_size = (130 * median_size) / 100 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    std::unordered_set<crypto::key_image> k_images;

    std::vector<transactions_container::iterator> tx_index(m_transactions.size());
    std::iota(tx_index.begin(),tx_index.end(),m_transactions.begin());
    std::sort(tx_index.begin(),
	      tx_index.end(),
	      [](transactions_container::iterator a, transactions_container::iterator b) -> bool
	      {
		return ((double)a->second.fee)/a->second.blob_size > ((double)b->second.fee)/b->second.blob_size;
	      });

    BOOST_FOREACH(auto it, tx_index)
    {
      transactions_container::value_type& tx = *it;
      
      if (tx.second.tx.vin.size() > 0) 
      {
        CHECKED_GET_SPECIFIC_VARIANT(tx.second.tx.vin[0], const txin_to_key, itk, false);

        // discourage < 3-way-mix transactions by mining them only as the first tx in an empty block
        if (n > 0 && itk.key_offsets.size() < 3)
          continue;
      }

      // Can not exceed maximum block size
      if (max_total_size < total_size + tx.second.blob_size)
        continue;

      // If adding this tx will make the block size
      // greater than CRYPTONOTE_GETBLOCKTEMPLATE_MAX
      // _BLOCK_SIZE bytes, reject the tx; this will 
      // keep block sizes from becoming too unwieldly
      // to propagate at 60s block times.
      if ( (total_size + tx.second.blob_size) > CRYPTONOTE_GETBLOCKTEMPLATE_MAX_BLOCK_SIZE )
        continue;

      // If we've exceeded the penalty free size,
      // stop including more tx
      if (total_size > median_size)
        break;      

      // Skip transactions that are not ready to be
      // included into the blockchain or that are
      // double spends of another transaction already in the template
      if (!is_transaction_ready_to_go(tx.second) || have_key_images(k_images, tx.second.tx))
        continue;

      bl.tx_hashes.push_back(tx.first);
      total_size += tx.second.blob_size;
      fee += tx.second.fee;
      append_key_images(k_images, tx.second.tx);
      n++;
    }

    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::init(const std::string& config_folder)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);

    m_config_folder = config_folder;
    std::string state_file_path = config_folder + "/" + CRYPTONOTE_POOLDATA_FILENAME;
    boost::system::error_code ec;
    if(!boost::filesystem::exists(state_file_path, ec))
      return true;
    bool res = tools::unserialize_obj_from_file(*this, state_file_path);
    if(!res)
    {
      LOG_ERROR("Failed to load memory pool from file " << state_file_path);

      m_transactions.clear();
      m_spent_key_images.clear();
    }

    for (auto it = m_transactions.begin(); it != m_transactions.end(); ) {
      CHECK_AND_ASSERT_MES(it->first == get_transaction_hash(it->second.tx),false,"corrupt tx pool containing id != hash");
      auto it2 = it++;
      if (it2->second.blob_size >= TRANSACTION_SIZE_LIMIT) {
        LOG_PRINT_L0("Transaction " << get_transaction_hash(it2->second.tx) << " is too big (" << it2->second.blob_size << " bytes), removing it from pool");
        remove_transaction_keyimages(it2->second.tx);
        m_transactions.erase(it2);
      }
    }

    // Ignore deserialization error
    return true;
  }

  //---------------------------------------------------------------------------------
  bool tx_memory_pool::deinit()
  {
    if (!tools::create_directories_if_necessary(m_config_folder))
    {
      LOG_PRINT_L0("Failed to create data directory: " << m_config_folder);
      return false;
    }

    std::string state_file_path = m_config_folder + "/" + CRYPTONOTE_POOLDATA_FILENAME;
    bool res = tools::serialize_obj_to_file(*this, state_file_path);
    if(!res)
    {
      LOG_PRINT_L0("Failed to serialize memory pool to file " << state_file_path);
    }
    return true;
  }
}
