#pragma once
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_core/cryptonote_basic.h"
#include "crypto/hash.h"
#include "wallet/wallet_rpc_server_error_codes.h"
#include "cryptonote_core/account.h"
#include "wallet/wallet2.h"
namespace web_wallet
{
namespace rpc
{
#define WALLET_RPC_STATUS_OK      "OK"
#define WALLET_RPC_STATUS_BUSY    "BUSY"
  struct transfer_details
  {
    uint64_t amount;
    bool spent;
    uint64_t global_index;
    std::string tx_hash;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(amount)
      KV_SERIALIZE(spent)
      KV_SERIALIZE(global_index)
      KV_SERIALIZE(tx_hash)
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_SET_WALLET
  {
    struct request
    {
      std::string seed;
      uint64_t account_create_time;
      uint64_t local_bc_height;
      std::string transfers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(seed)
        KV_SERIALIZE(account_create_time)
        KV_SERIALIZE(local_bc_height)
        KV_SERIALIZE(transfers)
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      std::string address;
      std::string key;
      std::string spend_key;
	    uint64_t 	 balance;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
        KV_SERIALIZE(key)
		    KV_SERIALIZE(spend_key)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct COMMAND_RPC_CREATE_WALLET
  {
    struct request
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      std::string seed;
      uint64_t account_create_time;
      uint64_t local_bc_height;
      std::string transfers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(seed)
        KV_SERIALIZE(account_create_time)
        KV_SERIALIZE(local_bc_height)
        KV_SERIALIZE(transfers)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct COMMAND_RPC_GET_BALANCE
  {

    struct request
    {
      std::string seed;
      uint64_t account_create_time;
      uint64_t local_bc_height;
      std::string transfers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(seed)
        KV_SERIALIZE(account_create_time)
        KV_SERIALIZE(local_bc_height)
        KV_SERIALIZE(transfers)
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      uint64_t balance;
      uint64_t unlocked_balance;
      uint64_t account_create_time;
      uint64_t local_bc_height;
      std::string transfers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(balance)
        KV_SERIALIZE(unlocked_balance)
        KV_SERIALIZE(account_create_time)
        KV_SERIALIZE(local_bc_height)
        KV_SERIALIZE(transfers)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct COMMAND_RPC_REFRESH
  {

    struct request
    {
      std::string seed;
      uint64_t account_create_time;
      uint64_t local_bc_height;
      std::string transfers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(seed)
        KV_SERIALIZE(account_create_time)
        KV_SERIALIZE(local_bc_height)
        KV_SERIALIZE(transfers)
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      uint64_t balance;
      uint64_t unlocked_balance;
      uint64_t account_create_time;
      uint64_t local_bc_height;
      std::string transfers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(balance)
        KV_SERIALIZE(unlocked_balance)
        KV_SERIALIZE(account_create_time)
        KV_SERIALIZE(local_bc_height)
        KV_SERIALIZE(transfers)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct COMMAND_RPC_GET_ADDRESS
  {
    struct request
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      std::string   address;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(address)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct transfer_destination
  {
    uint64_t amount;
    std::string address;
    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(amount)
      KV_SERIALIZE(address)
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_TRANSFER
  {
    struct request
    {
      std::list<transfer_destination> destinations;
      uint64_t fee;
      uint64_t mixin;
      uint64_t unlock_time;
      std::string payment_id;
      std::string seed;
      uint64_t account_create_time;
      uint64_t local_bc_height;
      std::string transfers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(destinations)
        KV_SERIALIZE(fee)
        KV_SERIALIZE(mixin)
        KV_SERIALIZE(unlock_time)
        KV_SERIALIZE(payment_id)
        KV_SERIALIZE(seed)
        KV_SERIALIZE(account_create_time)
        KV_SERIALIZE(local_bc_height)
        KV_SERIALIZE(transfers)
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      std::string tx_hash;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct COMMAND_RPC_TRANSFER_SPLIT
  {
    struct request
    {
      std::list<transfer_destination> destinations;
      uint64_t fee;
      uint64_t mixin;
      uint64_t unlock_time;
      std::string payment_id;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(destinations)
        KV_SERIALIZE(fee)
        KV_SERIALIZE(mixin)
        KV_SERIALIZE(unlock_time)
        KV_SERIALIZE(payment_id)
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      std::list<std::string> tx_hash_list;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(tx_hash_list)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct COMMAND_RPC_STORE
  {
    struct request
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };
  };

  struct payment_details
  {
    std::string payment_id;
    std::string tx_hash;
    uint64_t amount;
    uint64_t block_height;
    uint64_t unlock_time;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(payment_id)
      KV_SERIALIZE(tx_hash)
      KV_SERIALIZE(amount)
      KV_SERIALIZE(block_height)
      KV_SERIALIZE(unlock_time)
    END_KV_SERIALIZE_MAP()
  };

  struct COMMAND_RPC_GET_PAYMENTS
  {
    struct request
    {
      std::string payment_id;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payment_id)
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      std::list<payment_details> payments;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payments)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct COMMAND_RPC_GET_BULK_PAYMENTS
  {
    struct request
    {
      std::vector<std::string> payment_ids;
      uint64_t min_block_height;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payment_ids)
        KV_SERIALIZE(min_block_height)
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      std::list<payment_details> payments;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payments)
      END_KV_SERIALIZE_MAP()
    };
  };
  

  struct COMMAND_RPC_INCOMING_TRANSFERS
  {
    struct request
    {
      std::string transfer_type;
      std::string seed;
      uint64_t account_create_time;
      uint64_t local_bc_height;
      std::string transfers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(transfer_type)
        KV_SERIALIZE(seed)
        KV_SERIALIZE(account_create_time)
        KV_SERIALIZE(local_bc_height)
        KV_SERIALIZE(transfers)
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      std::list<transfer_details> transfers;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(transfers)
      END_KV_SERIALIZE_MAP()
    };
  };

  //JSON RPC V2
  struct COMMAND_RPC_QUERY_KEY
  {
    struct request
    {
      std::string key_type;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(key_type)
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      std::string key;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(key)
      END_KV_SERIALIZE_MAP()
    };
  };
}
}

