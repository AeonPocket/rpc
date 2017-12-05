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

#include "include_base_utils.h"
using namespace epee;

#include <chrono>
#include <iostream>
#include "rpc_server.h"
#include "common/command_line.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "cryptonote_core/account.h"
#include "rpc_server_commands_defs.h"
#include "misc_language.h"
#include "string_tools.h"
#include "crypto/hash.h"
#include "crypto/electrum-words.h"
#include "wallet/wallet2.h"

namespace web_wallet
{
  //-----------------------------------------------------------------------------------
  const command_line::arg_descriptor<std::string> rpc_server::arg_rpc_bind_port = {"rpc-bind-port", "Starts wallet as rpc server for wallet operations, sets bind port for server", "12345", true};
  const command_line::arg_descriptor<std::string> rpc_server::arg_rpc_bind_ip = {"rpc-bind-ip", "Specify ip to bind rpc server", "127.0.0.1"};
  boost::filesystem::path TEMP_DIR ("C:\\tmp");
  void rpc_server::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_rpc_bind_ip);
    command_line::add_arg(desc, arg_rpc_bind_port);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  rpc_server::rpc_server()
  {}
  //------------------------------------------------------------------------------------------------------------------------------
  
  // setterwallet
  
  bool rpc_server::run()
  {
    //DO NOT START THIS SERVER IN MORE THEN 1 THREADS WITHOUT REFACTORING
    return epee::http_server_impl_base<rpc_server, connection_context>::run(1, true);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool rpc_server::handle_command_line(const boost::program_options::variables_map& vm)
  {
    m_bind_ip = command_line::get_arg(vm, arg_rpc_bind_ip);
    m_port = command_line::get_arg(vm, arg_rpc_bind_port);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool rpc_server::init(const boost::program_options::variables_map& vm)
  {
    m_net_server.set_threads_prefix("RPC");
    bool r = handle_command_line(vm);
    CHECK_AND_ASSERT_MES(r, false, "Failed to process command line in core_rpc_server");
    return epee::http_server_impl_base<rpc_server, connection_context>::init(m_port, m_bind_ip);
  }
  
  
  //------------------------------------------------------------------------------------------------------------------------------
  bool rpc_server::on_set_wallet(const rpc::COMMAND_RPC_SET_WALLET::request& req, rpc::COMMAND_RPC_SET_WALLET::response& res, epee::json_rpc::error& er, rpc_server::connection_context& cntx)
  {
    try
    {
      crypto::secret_key recovery_param;
      crypto::ElectrumWords::words_to_bytes(req.seed, recovery_param);
      tools::wallet2* m_wallet = new tools::wallet2();
	  boost::filesystem::path l_path = web_wallet::TEMP_DIR / "wallet";
      m_wallet->generate(l_path.string(), "y", recovery_param, true, false);
      m_wallet->load(l_path.string(), "y");
      remove(l_path.string().c_str());
	  std::string l_path_address = l_path.string();
      remove(l_path_address.append(".address.txt").c_str());
	  std::string l_path_keys = l_path.string();
      remove(l_path_keys.append(".keys").c_str());
	 
      res.address = m_wallet->get_account().get_public_address_str();
      res.key = string_tools::pod_to_hex(m_wallet->get_account().get_keys().m_view_secret_key);
    }
    catch (std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool rpc_server::on_create_wallet(const rpc::COMMAND_RPC_CREATE_WALLET::request& req, rpc::COMMAND_RPC_CREATE_WALLET::response& res, epee::json_rpc::error& er, rpc_server::connection_context& cntx)
  {
    try
    {
      tools::wallet2* m_wallet = new tools::wallet2();
	  boost::filesystem::path l_path = web_wallet::TEMP_DIR / "wallet";
      crypto::secret_key recovery_param = m_wallet->generate(l_path.string(), "y");
      m_wallet->load(l_path.string(), "y");
      remove(l_path.string().c_str());
	  std::string l_path_address = l_path.string();
      remove(l_path_address.append(".address.txt").c_str());
	  std::string l_path_keys = l_path.string();
      remove(l_path_keys.append(".keys").c_str());
	  crypto::ElectrumWords::bytes_to_words(recovery_param, res.seed);
      res.address = m_wallet->get_account().get_public_address_str();
      res.key = string_tools::pod_to_hex(m_wallet->get_account().get_keys().m_view_secret_key);
    }
    catch (std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  ////------------------------------------------------------------------------------------------------------------------------------
  //bool rpc_server::on_getbalance(const rpc::COMMAND_RPC_GET_BALANCE::request& req, rpc::COMMAND_RPC_GET_BALANCE::response& res, epee::json_rpc::error& er, connection_context& cntx)
  //{
  //  try
  //  {
  //    res.balance = m_wallet.balance();
  //    res.unlocked_balance = m_wallet.unlocked_balance();
  //  }
  //  catch (std::exception& e)
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
  //    er.message = e.what();
  //    return false;
  //  }
  //  return true;
  //}
  ////------------------------------------------------------------------------------------------------------------------------------
  //bool rpc_server::on_getaddress(const rpc::COMMAND_RPC_GET_ADDRESS::request& req, rpc::COMMAND_RPC_GET_ADDRESS::response& res, epee::json_rpc::error& er, connection_context& cntx)
  //{
  //  try
  //  {
  //    res.address = m_wallet.get_account().get_public_address_str();
  //  }
  //  catch (std::exception& e)
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
  //    er.message = e.what();
  //    return false;
  //  }
  //  return true;
  //}

  ////------------------------------------------------------------------------------------------------------------------------------
  //bool rpc_server::validate_transfer(const std::list<rpc::transfer_destination> destinations, const std::string payment_id, std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t>& extra, epee::json_rpc::error& er)
  //{
  //  for (auto it = destinations.begin(); it != destinations.end(); it++)
  //  {
  //    cryptonote::tx_destination_entry de;
  //    if(!get_account_address_from_str(de.addr, it->address))
  //    {
  //      er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
  //      er.message = std::string("WALLET_RPC_ERROR_CODE_WRONG_ADDRESS: ") + it->address;
  //      return false;
  //    }
  //    de.amount = it->amount;
  //    dsts.push_back(de);
  //  }

  //  if (!payment_id.empty())
  //  {

  //    /* Just to clarify */
  //    const std::string& payment_id_str = payment_id;

  //    crypto::hash payment_id;
  //    /* Parse payment ID */
  //    if (!wallet2::parse_payment_id(payment_id_str, payment_id)) {
  //      er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
  //      er.message = "Payment id has invalid format: \"" + payment_id_str + "\", expected 64-character string";
  //      return false;
  //    }

  //    std::string extra_nonce;
  //    cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
  //    
  //    /* Append Payment ID data into extra */
  //    if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
  //      er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
  //      er.message = "Something went wront with payment_id. Please check its format: \"" + payment_id_str + "\", expected 64-character string";
  //      return false;
  //    }

  //  }
  //  return true;
  //}

  ////------------------------------------------------------------------------------------------------------------------------------
  //bool rpc_server::on_transfer(const rpc::COMMAND_RPC_TRANSFER::request& req, rpc::COMMAND_RPC_TRANSFER::response& res, epee::json_rpc::error& er, connection_context& cntx)
  //{

  //  std::vector<cryptonote::tx_destination_entry> dsts;
  //  std::vector<uint8_t> extra;

  //  // validate the transfer requested and populate dsts & extra
  //  if (!validate_transfer(req.destinations, req.payment_id, dsts, extra, er))
  //  {
  //    return false;
  //  }

  //  try
  //  {
  //    std::vector<wallet2::pending_tx> ptx_vector = m_wallet.create_transactions(dsts, req.mixin, req.unlock_time, req.fee, extra);

  //    // reject proposed transactions if there are more than one.  see on_transfer_split below.
  //    if (ptx_vector.size() != 1)
  //    {
  //      er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
  //      er.message = "Transaction would be too large.  try /transfer_split.";
  //      return false;
  //    }

  //    m_wallet.commit_tx(ptx_vector);

  //    // populate response with tx hash
  //    res.tx_hash = boost::lexical_cast<std::string>(cryptonote::get_transaction_hash(ptx_vector.back().tx));
  //    return true;
  //  }
  //  catch (const tools::error::daemon_busy& e)
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_DAEMON_IS_BUSY;
  //    er.message = e.what();
  //    return false;
  //  }
  //  catch (const std::exception& e)
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
  //    er.message = e.what();
  //    return false;
  //  }
  //  catch (...)
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
  //    er.message = "WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR";
  //    return false;
  //  }
  //  return true;
  //}
  ////------------------------------------------------------------------------------------------------------------------------------
  //bool rpc_server::on_transfer_split(const rpc::COMMAND_RPC_TRANSFER_SPLIT::request& req, rpc::COMMAND_RPC_TRANSFER_SPLIT::response& res, epee::json_rpc::error& er, connection_context& cntx)
  //{

  //  std::vector<cryptonote::tx_destination_entry> dsts;
  //  std::vector<uint8_t> extra;

  //  // validate the transfer requested and populate dsts & extra; RPC_TRANSFER::request and RPC_TRANSFER_SPLIT::request are identical types.
  //  if (!validate_transfer(req.destinations, req.payment_id, dsts, extra, er))
  //  {
  //    return false;
  //  }

  //  try
  //  {
  //    std::vector<wallet2::pending_tx> ptx_vector = m_wallet.create_transactions(dsts, req.mixin, req.unlock_time, req.fee, extra);

  //    m_wallet.commit_tx(ptx_vector);

  //    // populate response with tx hashes
  //    for (auto & ptx : ptx_vector)
  //    {
  //      res.tx_hash_list.push_back(boost::lexical_cast<std::string>(cryptonote::get_transaction_hash(ptx.tx)));
  //    }

  //    return true;
  //  }
  //  catch (const tools::error::daemon_busy& e)
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_DAEMON_IS_BUSY;
  //    er.message = e.what();
  //    return false;
  //  }
  //  catch (const std::exception& e)
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
  //    er.message = e.what();
  //    return false;
  //  }
  //  catch (...)
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
  //    er.message = "WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR";
  //    return false;
  //  }
  //  return true;
  //}
  ////------------------------------------------------------------------------------------------------------------------------------
  //bool rpc_server::on_store(const rpc::COMMAND_RPC_STORE::request& req, rpc::COMMAND_RPC_STORE::response& res, epee::json_rpc::error& er, connection_context& cntx)
  //{
  //  try
  //  {
  //    m_wallet.store();
  //  }
  //  catch (std::exception& e)
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
  //    er.message = e.what();
  //    return false;
  //  }
  //  return true;
  //}
  ////------------------------------------------------------------------------------------------------------------------------------
  //bool rpc_server::on_get_payments(const rpc::COMMAND_RPC_GET_PAYMENTS::request& req, rpc::COMMAND_RPC_GET_PAYMENTS::response& res, epee::json_rpc::error& er, connection_context& cntx)
  //{
  //  crypto::hash payment_id;
  //  cryptonote::blobdata payment_id_blob;
  //  if(!epee::string_tools::parse_hexstr_to_binbuff(req.payment_id, payment_id_blob))
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
  //    er.message = "Payment ID has invald format";
  //    return false;
  //  }

  //  if(sizeof(payment_id) != payment_id_blob.size())
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
  //    er.message = "Payment ID has invalid size";
  //    return false;
  //  }

  //  payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_blob.data());

  //  res.payments.clear();
  //  std::list<wallet2::payment_details> payment_list;
  //  m_wallet.get_payments(payment_id, payment_list);
  //  for (auto & payment : payment_list)
  //  {
  //    rpc_server::payment_details rpc_payment;
  //    rpc_payment.payment_id   = req.payment_id;
  //    rpc_payment.tx_hash      = epee::string_tools::pod_to_hex(payment.m_tx_hash);
  //    rpc_payment.amount       = payment.m_amount;
  //    rpc_payment.block_height = payment.m_block_height;
  //    rpc_payment.unlock_time  = payment.m_unlock_time;
  //    res.payments.push_back(rpc_payment);
  //  }

  //  return true;
  //}
  ////------------------------------------------------------------------------------------------------------------------------------
  //bool rpc_server::on_get_bulk_payments(const rpc::COMMAND_RPC_GET_BULK_PAYMENTS::request& req, rpc::COMMAND_RPC_GET_BULK_PAYMENTS::response& res, epee::json_rpc::error& er, connection_context& cntx)
  //{
  //  res.payments.clear();

  //  for (auto & payment_id_str : req.payment_ids)
  //  {
  //    crypto::hash payment_id;
  //    cryptonote::blobdata payment_id_blob;

  //    // TODO - should the whole thing fail because of one bad id?

  //    if(!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_blob))
  //    {
  //      er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
  //      er.message = "Payment ID has invalid format: " + payment_id_str;
  //      return false;
  //    }

  //    if(sizeof(payment_id) != payment_id_blob.size())
  //    {
  //      er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
  //      er.message = "Payment ID has invalid size: " + payment_id_str;
  //      return false;
  //    }

  //    payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_blob.data());

  //    std::list<wallet2::payment_details> payment_list;
  //    m_wallet.get_payments(payment_id, payment_list, req.min_block_height);

  //    for (auto & payment : payment_list)
  //    {
  //      rpc_server::payment_details rpc_payment;
  //      rpc_payment.payment_id   = payment_id_str;
  //      rpc_payment.tx_hash      = epee::string_tools::pod_to_hex(payment.m_tx_hash);
  //      rpc_payment.amount       = payment.m_amount;
  //      rpc_payment.block_height = payment.m_block_height;
  //      rpc_payment.unlock_time  = payment.m_unlock_time;
  //      res.payments.push_back(std::move(rpc_payment));
  //    }
  //  }

  //  return true;
  //}
  ////------------------------------------------------------------------------------------------------------------------------------
  //bool rpc_server::on_incoming_transfers(const rpc::COMMAND_RPC_INCOMING_TRANSFERS::request& req, rpc::COMMAND_RPC_INCOMING_TRANSFERS::response& res, epee::json_rpc::error& er, connection_context& cntx)
  //{
  //  if(req.transfer_type.compare("all") != 0 && req.transfer_type.compare("available") != 0 && req.transfer_type.compare("unavailable") != 0)
  //  {
  //    er.code = WALLET_RPC_ERROR_CODE_TRANSFER_TYPE;
  //    er.message = "Transfer type must be one of: all, available, or unavailable";
  //    return false;
  //  }

  //  bool filter = false;
  //  bool available = false;
  //  if (req.transfer_type.compare("available") == 0)
  //  {
  //    filter = true;
  //    available = true;
  //  }
  //  else if (req.transfer_type.compare("unavailable") == 0)
  //  {
  //    filter = true;
  //    available = false;
  //  }

  //  wallet2::transfer_container transfers;
  //  m_wallet.get_transfers(transfers);

  //  bool transfers_found = false;
  //  for (const auto& td : transfers)
  //  {
  //    if (!filter || available != td.m_spent)
  //    {
  //      if (!transfers_found)
  //      {
  //        transfers_found = true;
  //      }
  //      rpc_server::transfer_details rpc_transfers;
  //      rpc_transfers.amount       = td.amount();
  //      rpc_transfers.spent        = td.m_spent;
  //      rpc_transfers.global_index = td.m_global_output_index;
  //      rpc_transfers.tx_hash      = boost::lexical_cast<std::string>(cryptonote::get_transaction_hash(td.m_tx));
  //      res.transfers.push_back(rpc_transfers);
  //    }
  //  }

  //  if (!transfers_found)
  //  {
  //    return false;
  //  }
  //
  //  return true;
  //}
  ////------------------------------------------------------------------------------------------------------------------------------
  //bool rpc_server::on_query_key(const rpc::COMMAND_RPC_QUERY_KEY::request& req, rpc::COMMAND_RPC_QUERY_KEY::response& res, epee::json_rpc::error& er, connection_context& cntx)
  //{
  //    if (req.key_type.compare("mnemonic") == 0)
  //    {
  //      if (!m_wallet.get_seed(res.key))
  //      {
  //          er.message = "The wallet is non-deterministic. Cannot display seed.";
  //          return false;
  //      }
  //    }
  //    else if(req.key_type.compare("view_key") == 0)
  //    {
  //        res.key = string_tools::pod_to_hex(m_wallet.get_account().get_keys().m_view_secret_key);
  //    }
  //    else
  //    {
  //        er.message = "key_type " + req.key_type + " not found";
  //        return false;
  //    }

  //    return true;
  //}
}
