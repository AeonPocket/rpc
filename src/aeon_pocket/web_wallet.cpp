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
#include <boost/archive/text_iarchive.hpp>
#include <iostream>

#include <boost/utility/value_init.hpp>
#include "include_base_utils.h"
using namespace epee;

#include "web_wallet.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "misc_language.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "common/boost_serialization_helper.h"
#include "profile_tools.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"
#include "cryptonote_basic/blobdatatype.h"
#include "mnemonics/electrum-words.h"
#include "cryptonote_config.h"
extern "C"
{
#include "crypto/keccak.h"
#include "crypto/crypto-ops.h"
}
using namespace cryptonote;

namespace
{
	void do_prepare_file_names(const std::string& file_path, std::string& keys_file, std::string& wallet_file)
	{
		keys_file = file_path;
		wallet_file = file_path;
		boost::system::error_code e;
		if (string_tools::get_extension(keys_file) == "keys")
		{//provided keys file name
			wallet_file = string_tools::cut_off_extension(wallet_file);
		}
		else
		{//provided wallet file name
			keys_file += ".keys";
		}
	}

} //namespace

namespace aeon_pocket
{
	// for now, limit to 30 attempts.  TODO: discuss a good number to limit to.
	const size_t MAX_SPLIT_ATTEMPTS = 30;

	//----------------------------------------------------------------------------------------------------
	void web_wallet::init(const std::string& daemon_address, uint64_t upper_transaction_size_limit)
	{
		m_upper_transaction_size_limit = upper_transaction_size_limit;
		m_daemon_address = daemon_address;
		boost::optional<epee::net_utils::http::login> m_daemon_login;
    	m_http_client.set_server(m_daemon_address, m_daemon_login, false);
	}
	//----------------------------------------------------------------------------------------------------
	bool web_wallet::get_seed(std::string& electrum_words)
	{
		crypto::ElectrumWords::bytes_to_words(get_account().get_keys().m_spend_secret_key, electrum_words, "English");

		crypto::secret_key second;
		keccak((uint8_t *)&get_account().get_keys().m_spend_secret_key, sizeof(crypto::secret_key), (uint8_t *)&second, sizeof(crypto::secret_key));

		sc_reduce32((uint8_t *)&second);

		return memcmp(second.data, get_account().get_keys().m_view_secret_key.data, sizeof(crypto::secret_key)) == 0;
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::process_new_transaction(const cryptonote::transaction& tx, uint64_t height)
	{
		process_unconfirmed(tx);
		std::vector<size_t> outs;
		uint64_t tx_money_got_in_outs = 0;

		std::vector<tx_extra_field> tx_extra_fields;
		if (!parse_tx_extra(tx.extra, tx_extra_fields))
		{
			// Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
			LOG_PRINT_L0("Transaction extra has unsupported format: " << get_transaction_hash(tx));
		}

		tx_extra_pub_key pub_key_field;
		if (!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field))
		{
			LOG_PRINT_L0("Public key wasn't found in the transaction extra. Skipping transaction " << get_transaction_hash(tx));
			if (0 != m_callback)
				m_callback->on_skip_transaction(height, tx);
			return;
		}

		crypto::public_key tx_pub_key = pub_key_field.pub_key;
		bool r = lookup_acc_outs(m_account.get_keys(), tx, outs, tx_money_got_in_outs);
		THROW_AEON_POCKET_EXCEPTION_IF(!r, error::acc_outs_lookup_error, tx, tx_pub_key, m_account.get_keys());

		if (!outs.empty() && tx_money_got_in_outs)
		{
			//good news - got money! take care about it
			//usually we have only one transfer for user in transaction
			cryptonote::COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request req = AUTO_VAL_INIT(req);
			cryptonote::COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response res = AUTO_VAL_INIT(res);
			req.txid = get_transaction_hash(tx);
			bool r = net_utils::invoke_http_bin("/get_o_indexes.bin", req, res, m_http_client, WALLET_RCP_CONNECTION_TIMEOUT);
			THROW_AEON_POCKET_EXCEPTION_IF(!r, aeon_pocket::error::no_connection_to_daemon, "get_o_indexes.bin");
			THROW_AEON_POCKET_EXCEPTION_IF(res.status == CORE_RPC_STATUS_BUSY, error::daemon_busy, "get_o_indexes.bin");
			THROW_AEON_POCKET_EXCEPTION_IF(res.status != CORE_RPC_STATUS_OK, error::get_out_indices_error, res.status);
			THROW_AEON_POCKET_EXCEPTION_IF(res.o_indexes.size() != tx.vout.size(), error::wallet_internal_error,
				"transactions outputs size=" + std::to_string(tx.vout.size()) +
				" not match with COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES response size=" + std::to_string(res.o_indexes.size()));

			BOOST_FOREACH(size_t o, outs)
			{
				THROW_AEON_POCKET_EXCEPTION_IF(tx.vout.size() <= o, error::wallet_internal_error, "wrong out in transaction: internal index=" +
					std::to_string(o) + ", total_outs=" + std::to_string(tx.vout.size()));

				m_transfers.push_back(boost::value_initialized<transfer_details>());
				transfer_details& td = m_transfers.back();
				td.m_block_height = height;
				td.m_internal_output_index = o;
				td.m_global_output_index = res.o_indexes[o];
				td.m_tx = tx;
				td.m_spent = false;
				cryptonote::keypair in_ephemeral;
				std::unordered_map<crypto::public_key, subaddress_index> m_subaddresses;
				std::vector<crypto::public_key> additional_tx_pub_keys;
				crypto::key_image ki;
				// cryptonote::generate_key_image_helper(m_account.get_keys(), tx_pub_key, o, in_ephemeral, td.m_key_image);
				cryptonote::generate_key_image_helper(m_account.get_keys(), m_subaddresses, td.get_public_key(), tx_pub_key,  additional_tx_pub_keys, td.m_internal_output_index, in_ephemeral, ki, m_account.get_device());
				THROW_AEON_POCKET_EXCEPTION_IF(in_ephemeral.pub != boost::get<cryptonote::txout_to_key>(tx.vout[o].target).key,
					error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key");

				m_key_images[td.m_key_image] = m_transfers.size() - 1;
				LOG_PRINT_L0("Received money: " << print_money(td.amount()) << ", with tx: " << get_transaction_hash(tx));
				if (0 != m_callback)
					m_callback->on_money_received(height, td.m_tx, td.m_internal_output_index);
			}
		}

		uint64_t tx_money_spent_in_ins = 0;
		// check all outputs for spending (compare key images)
		BOOST_FOREACH(auto& in, tx.vin)
		{
			if (in.type() != typeid(cryptonote::txin_to_key))
				continue;
			auto it = m_key_images.find(boost::get<cryptonote::txin_to_key>(in).k_image);
			if (it != m_key_images.end())
			{
				LOG_PRINT_L0("Spent money: " << print_money(boost::get<cryptonote::txin_to_key>(in).amount) << ", with tx: " << get_transaction_hash(tx));
				tx_money_spent_in_ins += boost::get<cryptonote::txin_to_key>(in).amount;
				transfer_details& td = m_transfers[it->second];
				td.m_spent = true;
				if (0 != m_callback)
					m_callback->on_money_spent(height, td.m_tx, td.m_internal_output_index, tx);
			}
		}

		tx_extra_nonce extra_nonce;
		if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
		{
			crypto::hash payment_id;
			if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
			{
				uint64_t received = (tx_money_spent_in_ins < tx_money_got_in_outs) ? tx_money_got_in_outs - tx_money_spent_in_ins : 0;
				if (0 < received && crypto::null_hash != payment_id)
				{
					payment_details payment;
					payment.m_tx_hash = cryptonote::get_transaction_hash(tx);
					payment.m_amount = received;
					payment.m_block_height = height;
					payment.m_unlock_time = tx.unlock_time;
					m_payments.emplace(payment_id, payment);
					LOG_PRINT_L2("Payment found: " << payment_id << " / " << payment.m_tx_hash << " / " << payment.m_amount);
				}
			}
		}
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::process_new_transaction_2(const cryptonote::transaction& tx, uint64_t height, bool &found)
	{
		process_unconfirmed(tx);
		std::vector<size_t> outs;
		uint64_t tx_money_got_in_outs = 0;

		std::vector<tx_extra_field> tx_extra_fields;
		if (!parse_tx_extra(tx.extra, tx_extra_fields))
		{
			// Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
			LOG_PRINT_L0("Transaction extra has unsupported format: " << get_transaction_hash(tx));
		}

		tx_extra_pub_key pub_key_field;
		if (!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field))
		{
			LOG_PRINT_L0("Public key wasn't found in the transaction extra. Skipping transaction " << get_transaction_hash(tx));
			if (0 != m_callback)
				m_callback->on_skip_transaction(height, tx);
			return;
		}

		crypto::public_key tx_pub_key = pub_key_field.pub_key;
		bool r = lookup_acc_outs(m_account.get_keys(), tx, outs, tx_money_got_in_outs);
		THROW_AEON_POCKET_EXCEPTION_IF(!r, error::acc_outs_lookup_error, tx, tx_pub_key, m_account.get_keys());

		uint64_t tx_money_spent_in_ins = 0;
		// check all outputs for spending (compare key images)
		BOOST_FOREACH(auto& in, tx.vin)
		{
			if (in.type() != typeid(cryptonote::txin_to_key))
				continue;
			auto it = m_key_images.find(boost::get<cryptonote::txin_to_key>(in).k_image);
			if (it != m_key_images.end())
			{
				LOG_PRINT_L0("Spent money: " << print_money(boost::get<cryptonote::txin_to_key>(in).amount) << ", with tx: " << get_transaction_hash(tx));
				tx_money_spent_in_ins += boost::get<cryptonote::txin_to_key>(in).amount;
				transfer_details& td = m_transfers[it->second];
				td.m_spent = true;
				if (0 != m_callback)
					m_callback->on_money_spent(height, td.m_tx, td.m_internal_output_index, tx);
			}
		}

		if (!outs.empty() && tx_money_got_in_outs)
		{
			found = true;
			return;
		}

		tx_extra_nonce extra_nonce;
		if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
		{
			crypto::hash payment_id;
			if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
			{
				uint64_t received = (tx_money_spent_in_ins < tx_money_got_in_outs) ? tx_money_got_in_outs - tx_money_spent_in_ins : 0;
				if (0 < received && crypto::null_hash != payment_id)
				{
					payment_details payment;
					payment.m_tx_hash = cryptonote::get_transaction_hash(tx);
					payment.m_amount = received;
					payment.m_block_height = height;
					payment.m_unlock_time = tx.unlock_time;
					m_payments.emplace(payment_id, payment);
					LOG_PRINT_L2("Payment found: " << payment_id << " / " << payment.m_tx_hash << " / " << payment.m_amount);
				}
			}
		}
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::process_unconfirmed(const cryptonote::transaction& tx)
	{
		auto unconf_it = m_unconfirmed_txs.find(get_transaction_hash(tx));
		if (unconf_it != m_unconfirmed_txs.end())
			m_unconfirmed_txs.erase(unconf_it);
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::process_new_blockchain_entry(const cryptonote::block& b, cryptonote::block_complete_entry& bche, crypto::hash& bl_id, uint64_t height)
	{
		//handle transactions from new block

		//optimization: seeking only for blocks that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
		if (b.timestamp + 60 * 60 * 24 > m_account.get_createtime())
		{
			TIME_MEASURE_START(miner_tx_handle_time);
			process_new_transaction(b.miner_tx, height);
			TIME_MEASURE_FINISH(miner_tx_handle_time);

			TIME_MEASURE_START(txs_handle_time);
			BOOST_FOREACH(auto& txblob, bche.txs)
			{
				cryptonote::transaction tx;
				bool r = parse_and_validate_tx_from_blob(txblob, tx);
				THROW_AEON_POCKET_EXCEPTION_IF(!r, error::tx_parse_error, txblob);
				process_new_transaction(tx, height);
			}
			TIME_MEASURE_FINISH(txs_handle_time);
			LOG_PRINT_L2("Processed block: " << bl_id << ", height " << height << ", " << miner_tx_handle_time + txs_handle_time << "(" << miner_tx_handle_time << "/" << txs_handle_time << ")ms");
		}
		else
		{
			LOG_PRINT_L2("Skipped block by timestamp, height: " << height << ", block time " << b.timestamp << ", account time " << m_account.get_createtime());
		}
		m_blockchain.push_back(bl_id);
		++m_local_bc_height;

		if (0 != m_callback)
			m_callback->on_new_block(height, b);
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::get_short_chain_history(std::list<crypto::hash>& ids)
	{
		size_t i = 0;
		size_t current_multiplier = 1;
		size_t sz = m_blockchain.size();
		if (!sz)
			return;
		size_t current_back_offset = 1;
		bool genesis_included = false;
		while (current_back_offset < sz)
		{
			ids.push_back(m_blockchain[sz - current_back_offset]);
			if (sz - current_back_offset == 0)
				genesis_included = true;
			if (i < 10)
			{
				++current_back_offset;
			}
			else
			{
				current_back_offset += current_multiplier *= 2;
			}
			++i;
		}
		if (!genesis_included)
			ids.push_back(m_blockchain[0]);
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::pull_blocks(uint64_t start_height, size_t& blocks_added)
	{
		blocks_added = 0;
		cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req = AUTO_VAL_INIT(req);
		cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res = AUTO_VAL_INIT(res);
		get_short_chain_history(req.block_ids);
		req.start_height = start_height;
		bool r = net_utils::invoke_http_bin("/getblocks.bin", req, res, m_http_client, WALLET_RCP_CONNECTION_TIMEOUT);
		THROW_AEON_POCKET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "getblocks.bin");
		THROW_AEON_POCKET_EXCEPTION_IF(res.status == CORE_RPC_STATUS_BUSY, error::daemon_busy, "getblocks.bin");
		THROW_AEON_POCKET_EXCEPTION_IF(res.status != CORE_RPC_STATUS_OK, error::get_blocks_error, res.status);

		size_t current_index = res.start_height;
		BOOST_FOREACH(auto& bl_entry, res.blocks)
		{
			cryptonote::block bl;
			r = cryptonote::parse_and_validate_block_from_blob(bl_entry.block, bl);
			THROW_AEON_POCKET_EXCEPTION_IF(!r, error::block_parse_error, bl_entry.block);

			crypto::hash bl_id = get_block_hash(bl);
			if (current_index >= m_blockchain.size())
			{
				process_new_blockchain_entry(bl, bl_entry, bl_id, current_index);
				++blocks_added;
			}
			else if (bl_id != m_blockchain[current_index])
			{
				//split detected here !!!
				THROW_AEON_POCKET_EXCEPTION_IF(current_index == res.start_height, error::wallet_internal_error,
					"wrong daemon response: split starts from the first block in response " + string_tools::pod_to_hex(bl_id) +
					" (height " + std::to_string(res.start_height) + "), local block id at this height: " +
					string_tools::pod_to_hex(m_blockchain[current_index]));

				detach_blockchain(current_index);
				process_new_blockchain_entry(bl, bl_entry, bl_id, current_index);
			}
			else
			{
				LOG_PRINT_L2("Block is already in blockchain: " << string_tools::pod_to_hex(bl_id));
			}

			++current_index;
		}
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::refresh()
	{
		size_t blocks_fetched = 0;
		refresh(0, blocks_fetched);
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::refresh(uint64_t start_height, size_t & blocks_fetched)
	{
		bool received_money = false;
		refresh(start_height, blocks_fetched, received_money);
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::refresh(uint64_t start_height, size_t & blocks_fetched, bool& received_money)
	{
		received_money = false;
		blocks_fetched = 0;
		size_t added_blocks = 0;
		size_t try_count = 0;
		crypto::hash last_tx_hash_id = m_transfers.size() ? get_transaction_hash(m_transfers.back().m_tx) :crypto::null_hash;

		while (m_run.load(std::memory_order_relaxed))
		{
			try
			{
				pull_blocks(start_height, added_blocks);
				blocks_fetched += added_blocks;
				if (!added_blocks)
					break;
			}
			catch (const std::exception&)
			{
				blocks_fetched += added_blocks;
				if (try_count < 3)
				{
					LOG_PRINT_L1("Another try pull_blocks (try_count=" << try_count << ")...");
					++try_count;
				}
				else
				{
					LOG_ERROR("pull_blocks failed, try_count=" << try_count);
					throw;
				}
			}
		}
		if (last_tx_hash_id != (m_transfers.size() ? get_transaction_hash(m_transfers.back().m_tx) : crypto::null_hash))
			received_money = true;

		LOG_PRINT_L1("Refresh done, blocks received: " << blocks_fetched << ", balance: " << print_money(balance()) << ", unlocked: " << print_money(unlocked_balance()));
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::refresh_from_local_bc(std::list<std::string>& txs_hashes)
	{
		size_t blocks_fetched = 0;
		size_t added_blocks = 0;
		size_t try_count = 0;

		while (m_run.load(std::memory_order_relaxed))
		{
			try
			{
				added_blocks = 0;
				cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req = AUTO_VAL_INIT(req);
				cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res = AUTO_VAL_INIT(res);
				get_short_chain_history(req.block_ids);
				req.start_height = m_local_bc_height;
				bool r = net_utils::invoke_http_bin("/getblocks.bin", req, res, m_http_client, WALLET_RCP_CONNECTION_TIMEOUT);
				THROW_AEON_POCKET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "getblocks.bin");
				THROW_AEON_POCKET_EXCEPTION_IF(res.status == CORE_RPC_STATUS_BUSY, error::daemon_busy, "getblocks.bin");
				THROW_AEON_POCKET_EXCEPTION_IF(res.status != CORE_RPC_STATUS_OK, error::get_blocks_error, res.status);

				size_t current_index = res.start_height;
				BOOST_FOREACH(auto& bl_entry, res.blocks)
				{
					cryptonote::block bl;
					cryptonote::transaction tx;
					r = cryptonote::parse_and_validate_block_from_blob(bl_entry.block, bl);
					THROW_AEON_POCKET_EXCEPTION_IF(!r, error::block_parse_error, bl_entry.block);

					crypto::hash bl_id = get_block_hash(bl);
					if (current_index >= m_blockchain.size())
					{
						process_new_blockchain_entry_2(bl, bl_entry, bl_id, current_index, txs_hashes);
						//++blocks_added;
						++added_blocks;
					}
					else if (bl_id != m_blockchain[current_index])
					{
						//split detected here !!!
						THROW_AEON_POCKET_EXCEPTION_IF(current_index == res.start_height, error::wallet_internal_error,
							"wrong daemon response: split starts from the first block in response " + string_tools::pod_to_hex(bl_id) +
							" (height " + std::to_string(res.start_height) + "), local block id at this height: " +
							string_tools::pod_to_hex(m_blockchain[current_index]));

						detach_blockchain(current_index);
						process_new_blockchain_entry(bl, bl_entry, bl_id, current_index);
					}
					else
					{
						LOG_PRINT_L2("Block is already in blockchain: " << string_tools::pod_to_hex(bl_id));
					}
					if (!txs_hashes.empty()) {
						break;
					}
					++current_index;
				}
				blocks_fetched += added_blocks;
				if (!added_blocks || !txs_hashes.empty())
					break;
			}
			catch (const std::exception&)
			{
				blocks_fetched += added_blocks;
				if (try_count < 3)
				{
					LOG_PRINT_L1("Another try pull_blocks (try_count=" << try_count << ")...");
					++try_count;
				}
				else
				{
					LOG_ERROR("pull_blocks failed, try_count=" << try_count);
					throw;
				}
			}
		}
		m_blockchain.resize(m_local_bc_height + blocks_fetched);
		LOG_PRINT_L1("Refresh done, blocks received: " << blocks_fetched << ", balance: " << print_money(balance()) << ", unlocked: " << print_money(unlocked_balance()));
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::update_wallet(transfer_details td, cryptonote::transaction tx, crypto::public_key tx_pub_key, size_t o) {
//		cryptonote::keypair in_ephemeral;
		// cryptonote::generate_key_image_helper(m_account.get_keys(), tx_pub_key, o, in_ephemeral, keyimage);
//		std::unordered_map<crypto::public_key, subaddress_index> m_subaddresses;
//		std::vector<crypto::public_key> additional_tx_pub_keys;
//		crypto::key_image ki;
//		cryptonote::generate_key_image_helper(m_account.get_keys(), m_subaddresses, td.get_public_key(), tx_pub_key,  additional_tx_pub_keys, td.m_internal_output_index, in_ephemeral, ki, m_account.get_device());
//		THROW_AEON_POCKET_EXCEPTION_IF(in_ephemeral.pub != boost::get<cryptonote::txout_to_key>(tx.vout[o].target).key,
//			error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key");

		m_transfers.push_back(td);
		m_key_images[td.m_key_image] = m_transfers.size() - 1;
		LOG_PRINT_L0("Received money: " << print_money(td.amount()) << ", with tx: " << get_transaction_hash(tx));
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::process_new_blockchain_entry_2(const cryptonote::block& b, cryptonote::block_complete_entry& bche, crypto::hash& bl_id, uint64_t height, std::list<std::string>& tx_hashes)
	{
		//handle transactions from new block

		//optimization: seeking only for blocks that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
		if (b.timestamp + 60 * 60 * 24 > m_account.get_createtime())
		{
			TIME_MEASURE_START(miner_tx_handle_time);
			process_new_transaction(b.miner_tx, height);
			TIME_MEASURE_FINISH(miner_tx_handle_time);

			TIME_MEASURE_START(txs_handle_time);
			BOOST_FOREACH(auto& txblob, bche.txs)
			{
				bool found = false;
				cryptonote::transaction tx;
				bool r = parse_and_validate_tx_from_blob(txblob, tx);

				THROW_AEON_POCKET_EXCEPTION_IF(!r, error::tx_parse_error, txblob);
				process_new_transaction_2(tx, height, found);
				if (found) {
					crypto::hash hash = get_transaction_hash(tx);
					tx_hashes.push_back(string_tools::pod_to_hex(hash));
				}
			}
			TIME_MEASURE_FINISH(txs_handle_time);
			if (!tx_hashes.empty()) {
				return;
			}
			//		LOG_PRINT_L2("Processed block: " << bl_id << ", height " << height << ", " << miner_tx_handle_time + txs_handle_time << "(" << miner_tx_handle_time << "/" << txs_handle_time << ")ms" << get_transaction_hash(tx)) ;
		}
		else
		{
			LOG_PRINT_L2("Skipped block by timestamp, height: " << height << ", block time " << b.timestamp << ", account time " << m_account.get_createtime());
		}
		m_blockchain.push_back(bl_id);
		++m_local_bc_height;

		if (0 != m_callback)
			m_callback->on_new_block(height, b);
	}
	//----------------------------------------------------------------------------------------------------
	bool web_wallet::refresh(size_t & blocks_fetched, bool& received_money, bool& ok)
	{
		try
		{
			refresh(0, blocks_fetched, received_money);
			ok = true;
		}
		catch (...)
		{
			ok = false;
		}
		return ok;
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::detach_blockchain(uint64_t height)
	{
		LOG_PRINT_L0("Detaching blockchain on height " << height);
		size_t transfers_detached = 0;

		auto it = std::find_if(m_transfers.begin(), m_transfers.end(), [&](const transfer_details& td) {return td.m_block_height >= height; });
		size_t i_start = it - m_transfers.begin();

		for (size_t i = i_start; i != m_transfers.size(); i++)
		{
			auto it_ki = m_key_images.find(m_transfers[i].m_key_image);
			THROW_AEON_POCKET_EXCEPTION_IF(it_ki == m_key_images.end(), error::wallet_internal_error, "key image not found");
			m_key_images.erase(it_ki);
			++transfers_detached;
		}
		m_transfers.erase(it, m_transfers.end());

		size_t blocks_detached = m_blockchain.end() - (m_blockchain.begin() + height);
		m_blockchain.erase(m_blockchain.begin() + height, m_blockchain.end());
		m_local_bc_height -= blocks_detached;

		for (auto it = m_payments.begin(); it != m_payments.end(); )
		{
			if (height <= it->second.m_block_height)
				it = m_payments.erase(it);
			else
				++it;
		}

		LOG_PRINT_L0("Detached blockchain on height " << height << ", transfers detached " << transfers_detached << ", blocks detached " << blocks_detached);
	}
	//----------------------------------------------------------------------------------------------------
	bool web_wallet::deinit()
	{
		return true;
	}
	//----------------------------------------------------------------------------------------------------
	bool web_wallet::clear()
	{
		m_blockchain.clear();
		m_transfers.clear();
		cryptonote::block b;
		//cryptonote::generate_genesis_block(b);
		cryptonote::generate_genesis_block(b,config::GENESIS_TX, config::GENESIS_NONCE);
		m_blockchain.push_back(get_block_hash(b));
		m_local_bc_height = 1;
		return true;
	}
	//----------------------------------------------------------------------------------------------------
	bool web_wallet::store_keys(const std::string& keys_file_name, const std::string& password)
	{
		std::string account_data;
		bool r = epee::serialization::store_t_to_binary(m_account, account_data);
		CHECK_AND_ASSERT_MES(r, false, "failed to serialize wallet keys");
		web_wallet::keys_file_data keys_file_data = boost::value_initialized<web_wallet::keys_file_data>();

		crypto::chacha_key key;
		crypto::generate_chacha_key(password, key);
		std::string cipher;
		cipher.resize(account_data.size());
		keys_file_data.iv = crypto::rand<crypto::chacha_iv>();
		crypto::chacha8(account_data.data(), account_data.size(), key, keys_file_data.iv, &cipher[0]);
		keys_file_data.account_data = cipher;

		std::string buf;
		r = ::serialization::dump_binary(keys_file_data, buf);
		r = r && epee::file_io_utils::save_string_to_file(keys_file_name, buf); //and never touch wallet_keys_file again, only read
		CHECK_AND_ASSERT_MES(r, false, "failed to generate wallet keys file " << keys_file_name);

		return true;
	}
	//----------------------------------------------------------------------------------------------------
	namespace
	{
		bool verify_keys(const crypto::secret_key& sec, const crypto::public_key& expected_pub)
		{
			crypto::public_key pub;
			bool r = crypto::secret_key_to_public_key(sec, pub);
			return r && expected_pub == pub;
		}
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::load_keys(const std::string& keys_file_name, const std::string& password)
	{
		web_wallet::keys_file_data keys_file_data;
		std::string buf;
		bool r = epee::file_io_utils::load_file_to_string(keys_file_name, buf);
		THROW_AEON_POCKET_EXCEPTION_IF(!r, error::file_read_error, keys_file_name);
		r = ::serialization::parse_binary(buf, keys_file_data);
		THROW_AEON_POCKET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize \"" + keys_file_name + '\"');

		crypto::chacha_key key;
		crypto::generate_chacha_key(password, key);
		std::string account_data;
		account_data.resize(keys_file_data.account_data.size());
		crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);

		const cryptonote::account_keys& keys = m_account.get_keys();
		r = epee::serialization::load_t_from_binary(m_account, account_data);
		r = r && verify_keys(keys.m_view_secret_key, keys.m_account_address.m_view_public_key);
		r = r && verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
		THROW_AEON_POCKET_EXCEPTION_IF(!r, error::invalid_password);
	}
	//----------------------------------------------------------------------------------------------------
	crypto::secret_key web_wallet::generate(const std::string& wallet_, const std::string& password, const crypto::secret_key& recovery_param, bool recover, bool two_random)
	{
		clear();
		prepare_file_names(wallet_);

		boost::system::error_code ignored_ec;
		THROW_AEON_POCKET_EXCEPTION_IF(boost::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
		THROW_AEON_POCKET_EXCEPTION_IF(boost::filesystem::exists(m_keys_file, ignored_ec), error::file_exists, m_keys_file);

		crypto::secret_key retval = m_account.generate(recovery_param, recover, two_random);

		m_account_public_address = m_account.get_keys().m_account_address;

		bool r = store_keys(m_keys_file, password);
		THROW_AEON_POCKET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);

		r = file_io_utils::save_string_to_file(m_wallet_file + ".address.txt", m_account.get_public_address_str());
		//if (!r) LOG_PRINT_RED_L0("String with address text not saved");

		store();
		return retval;
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::wallet_exists(const std::string& file_path, bool& keys_file_exists, bool& wallet_file_exists)
	{
		std::string keys_file, wallet_file;
		do_prepare_file_names(file_path, keys_file, wallet_file);

		boost::system::error_code ignore;
		keys_file_exists = boost::filesystem::exists(keys_file, ignore);
		wallet_file_exists = boost::filesystem::exists(wallet_file, ignore);
	}
	//----------------------------------------------------------------------------------------------------
	bool web_wallet::parse_payment_id(const std::string& payment_id_str, crypto::hash& payment_id)
	{
		cryptonote::blobdata payment_id_data;
		if (!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data))
			return false;

		if (sizeof(crypto::hash) != payment_id_data.size())
			return false;

		payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_data.data());
		return true;
	}
	//----------------------------------------------------------------------------------------------------
	bool web_wallet::prepare_file_names(const std::string& file_path)
	{
		do_prepare_file_names(file_path, m_keys_file, m_wallet_file);
		return true;
	}
	//----------------------------------------------------------------------------------------------------
	bool web_wallet::check_connection()
	{
		if (m_http_client.is_connected())
			return true;

		net_utils::http::url_content u;
		net_utils::parse_url(m_daemon_address, u);
		if (!u.port)
			u.port = config::RPC_DEFAULT_PORT;
		//return m_http_client.connect(u.host, std::to_string(u.port), WALLET_RCP_CONNECTION_TIMEOUT);
		return m_http_client.connect( WALLET_RCP_CONNECTION_TIMEOUT);
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::load(const std::string& wallet_, const std::string& password)
	{
		clear();
		prepare_file_names(wallet_);

		boost::system::error_code e;
		bool exists = boost::filesystem::exists(m_keys_file, e);
		THROW_AEON_POCKET_EXCEPTION_IF(e || !exists, error::file_not_found, m_keys_file);

		load_keys(m_keys_file, password);
		LOG_PRINT_L0("Loaded wallet keys file, with public address: " << m_account.get_public_address_str());

		//keys loaded ok!
		//try to load wallet file. but even if we failed, it is not big problem
		if (!boost::filesystem::exists(m_wallet_file, e) || e)
		{
			LOG_PRINT_L0("file not found: " << m_wallet_file << ", starting with empty blockchain");
			m_account_public_address = m_account.get_keys().m_account_address;
			return;
		}
		bool r = tools::unserialize_obj_from_file(*this, m_wallet_file);
		THROW_AEON_POCKET_EXCEPTION_IF(!r, error::file_read_error, m_wallet_file);
		THROW_AEON_POCKET_EXCEPTION_IF(
			m_account_public_address.m_spend_public_key != m_account.get_keys().m_account_address.m_spend_public_key ||
			m_account_public_address.m_view_public_key != m_account.get_keys().m_account_address.m_view_public_key,
			error::wallet_files_doesnt_correspond, m_keys_file, m_wallet_file);

		if (m_blockchain.empty())
		{
			cryptonote::block b;
			cryptonote::generate_genesis_block(b,config::GENESIS_TX, config::GENESIS_NONCE);
			m_blockchain.push_back(get_block_hash(b));
		}
		m_local_bc_height = m_blockchain.size();
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::load(uint64_t account_create_time, uint64_t local_bc_height, std::string transfers, std::string address, std::string view_key, std::string key_images) {
		crypto::secret_key m_account_view_key;
		cryptonote::address_parse_info info;
		get_account_address_from_str(info,cryptonote::network_type::MAINNET, address);
		string_tools::hex_to_pod(view_key, m_account_view_key);

		bool c = verify_keys(m_account_view_key, info.address.m_view_public_key);
		THROW_AEON_POCKET_EXCEPTION_IF(!c, error::invalid_password);

		m_account.generate(info.address, m_account_view_key);

		m_account.set_createtime(account_create_time);
		m_local_bc_height = local_bc_height;
		std::stringstream ss;
		ss.str(transfers);
		boost::archive::text_iarchive ia{ ss };
		ia >> m_transfers;

		std::stringstream ss2;
		ss2.str(key_images);
		boost::archive::text_iarchive ib{ ss2 };
		ib >> m_key_images;

		m_blockchain.resize(m_local_bc_height);
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::store()
	{
		bool r = tools::serialize_obj_to_file(*this, m_wallet_file);
		THROW_AEON_POCKET_EXCEPTION_IF(!r, error::file_save_error, m_wallet_file);
	}
	//----------------------------------------------------------------------------------------------------
	uint64_t web_wallet::unlocked_balance()
	{
		uint64_t amount = 0;
		BOOST_FOREACH(transfer_details& td, m_transfers)
			if (!td.m_spent && is_transfer_unlocked(td))
				amount += td.amount();

		return amount;
	}
	//----------------------------------------------------------------------------------------------------
	uint64_t web_wallet::balance()
	{
		uint64_t amount = 0;
		BOOST_FOREACH(auto& td, m_transfers)
			if (!td.m_spent)
				amount += td.amount();


		BOOST_FOREACH(auto& utx, m_unconfirmed_txs)
			amount += utx.second.m_change;

		return amount;
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::get_transfers(web_wallet::transfer_container& incoming_transfers) const
	{
		incoming_transfers = m_transfers;
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::get_key_images(std::unordered_map<crypto::key_image, size_t>& key_images) const
	{
		key_images = m_key_images;
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::get_payments(const crypto::hash& payment_id, std::list<web_wallet::payment_details>& payments, uint64_t min_height) const
	{
		auto range = m_payments.equal_range(payment_id);
		std::for_each(range.first, range.second, [&payments, &min_height](const payment_container::value_type& x) {
			if (min_height < x.second.m_block_height)
			{
				payments.push_back(x.second);
			}
		});
	}
	//----------------------------------------------------------------------------------------------------
	bool web_wallet::is_transfer_unlocked(const transfer_details& td) const
	{
		if (!is_tx_spendtime_unlocked(td.m_tx.unlock_time))
			return false;

		if (td.m_block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE> m_blockchain.size())
			return false;

		return true;
	}
	//----------------------------------------------------------------------------------------------------
	bool web_wallet::is_tx_spendtime_unlocked(uint64_t unlock_time) const
	{
		if (unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
		{
			//interpret as block index
			if (m_blockchain.size() - 1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
				return true;
			else
				return false;
		}
		else
		{
			//interpret as time
			uint64_t current_time = static_cast<uint64_t>(time(NULL));
			if (current_time +  CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2 >= unlock_time)
				return true;
			else
				return false;
		}
		return false;
	}
	//----------------------------------------------------------------------------------------------------
	namespace
	{
		template<typename T>
		T pop_random_value(std::vector<T>& vec)
		{
			CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");

			size_t idx = crypto::rand<size_t>() % vec.size();
			T res = vec[idx];
			if (idx + 1 != vec.size())
			{
				vec[idx] = vec.back();
			}
			vec.resize(vec.size() - 1);

			return res;
		}
	}
	//----------------------------------------------------------------------------------------------------
	// Select random input sources for transaction.
	// returns:
	//    direct return: amount of money found
	//    modified reference: selected_transfers, a list of iterators/indices of input sources
	uint64_t web_wallet::select_transfers(uint64_t needed_money, bool add_dust, uint64_t dust, std::list<transfer_container::iterator>& selected_transfers)
	{
		std::vector<size_t> unused_transfers_indices;
		std::vector<size_t> unused_dust_indices;

		// aggregate sources available for transfers
		// if dust needed, take dust from only one source (so require source has at least dust amount)
		for (size_t i = 0; i < m_transfers.size(); ++i)
		{
			const transfer_details& td = m_transfers[i];
			if (!td.m_spent && is_transfer_unlocked(td))
			{
				if (dust < td.amount())
					unused_transfers_indices.push_back(i);
				else
					unused_dust_indices.push_back(i);
			}
		}

		bool select_one_dust = add_dust && !unused_dust_indices.empty();
		uint64_t found_money = 0;
		while (found_money < needed_money && (!unused_transfers_indices.empty() || !unused_dust_indices.empty()))
		{
			size_t idx;
			if (select_one_dust)
			{
				idx = pop_random_value(unused_dust_indices);
				select_one_dust = false;
			}
			else
			{
				idx = !unused_transfers_indices.empty() ? pop_random_value(unused_transfers_indices) : pop_random_value(unused_dust_indices);
			}

			transfer_container::iterator it = m_transfers.begin() + idx;
			selected_transfers.push_back(it);
			found_money += it->amount();
		}

		return found_money;
	}
	//----------------------------------------------------------------------------------------------------
	void web_wallet::add_unconfirmed_tx(const cryptonote::transaction& tx, uint64_t change_amount)
	{
		unconfirmed_transfer_details& utd = m_unconfirmed_txs[cryptonote::get_transaction_hash(tx)];
		utd.m_change = change_amount;
		utd.m_sent_time = time(NULL);
		utd.m_tx = tx;
	}

	  //----------------------------------------------------------------------------------------------------
	  // take a pending tx and actually send it to the daemon
	void web_wallet::commit_tx(pending_tx& ptx)
	{
		using namespace cryptonote;
		COMMAND_RPC_SEND_RAW_TX::request req;
		req.tx_as_hex = epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(ptx.tx));
		COMMAND_RPC_SEND_RAW_TX::response daemon_send_resp;
		bool r = epee::net_utils::invoke_http_json("/sendrawtransaction", req, daemon_send_resp, m_http_client,std::chrono::minutes(3) + std::chrono::seconds(30) );
		THROW_AEON_POCKET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "sendrawtransaction");
		THROW_AEON_POCKET_EXCEPTION_IF(daemon_send_resp.status == CORE_RPC_STATUS_BUSY, error::daemon_busy, "sendrawtransaction");
		THROW_AEON_POCKET_EXCEPTION_IF(daemon_send_resp.status != CORE_RPC_STATUS_OK, error::tx_rejected, ptx.tx, daemon_send_resp.status);

		add_unconfirmed_tx(ptx.tx, ptx.change_dts.amount);

		LOG_PRINT_L2("transaction " << get_transaction_hash(ptx.tx) << " generated ok and sent to daemon, key_images: [" << ptx.key_images << "]");

		BOOST_FOREACH(transfer_container::iterator it, ptx.selected_transfers)
			it->m_spent = true;

		LOG_PRINT_L0("Transaction successfully sent. <" << get_transaction_hash(ptx.tx) << ">" << ENDL
			<< "Commission: " << print_money(ptx.fee + ptx.dust) << " (dust: " << print_money(ptx.dust) << ")" << ENDL
			<< "Balance: " << print_money(balance()) << ENDL
			<< "Unlocked: " << print_money(unlocked_balance()) << ENDL
			<< "Please, wait for confirmation for your balance to be unlocked.");
	}

	void web_wallet::commit_tx(std::vector<pending_tx>& ptx_vector)
	{
		for (auto & ptx : ptx_vector)
		{
			commit_tx(ptx);
		}
	}
}
