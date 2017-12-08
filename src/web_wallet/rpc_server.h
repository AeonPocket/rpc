#pragma  once

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include "net/http_server_impl_base.h"
#include "rpc_server_commands_defs.h"
#include "wallet/wallet2.h"
#include "common/command_line.h"
namespace web_wallet
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class rpc_server: public epee::http_server_impl_base<rpc_server>
  {
  public:
    typedef epee::net_utils::connection_context_base connection_context;

    rpc_server();

    const static command_line::arg_descriptor<std::string> arg_rpc_bind_port;
    const static command_line::arg_descriptor<std::string> arg_rpc_bind_ip;
	bool set_daemon_address(std::string &daemon_address);
    static void init_options(boost::program_options::options_description& desc);
    bool init(const boost::program_options::variables_map& vm);
    bool run();
  private:

    CHAIN_HTTP_TO_MAP2(connection_context); //forward http requests to uri map

    BEGIN_URI_MAP2()
      BEGIN_JSON_RPC_MAP("/json_rpc")
        MAP_JON_RPC_WE("set_wallet",         on_set_wallet,        rpc::COMMAND_RPC_SET_WALLET)
        MAP_JON_RPC_WE("create_wallet",      on_create_wallet,     rpc::COMMAND_RPC_CREATE_WALLET)
        MAP_JON_RPC_WE("getbalance",         on_getbalance,        rpc::COMMAND_RPC_GET_BALANCE)
        MAP_JON_RPC_WE("refresh",            on_refresh,           rpc::COMMAND_RPC_REFRESH)
      //  MAP_JON_RPC_WE("getaddress",         on_getaddress,         rpc::COMMAND_RPC_GET_ADDRESS)
      //  MAP_JON_RPC_WE("transfer",           on_transfer,           rpc::COMMAND_RPC_TRANSFER)
      //  MAP_JON_RPC_WE("transfer_split",     on_transfer_split,     rpc::COMMAND_RPC_TRANSFER_SPLIT)
      //  MAP_JON_RPC_WE("store",              on_store,              rpc::COMMAND_RPC_STORE)
      //  MAP_JON_RPC_WE("get_payments",       on_get_payments,       rpc::COMMAND_RPC_GET_PAYMENTS)
      //  MAP_JON_RPC_WE("get_bulk_payments",  on_get_bulk_payments,  rpc::COMMAND_RPC_GET_BULK_PAYMENTS)
      //  MAP_JON_RPC_WE("incoming_transfers", on_incoming_transfers, rpc::COMMAND_RPC_INCOMING_TRANSFERS)
      //  MAP_JON_RPC_WE("query_key",         on_query_key,         rpc::COMMAND_RPC_QUERY_KEY)
      END_JSON_RPC_MAP()
    END_URI_MAP2()

      //json_rpc
      bool on_set_wallet(const rpc::COMMAND_RPC_SET_WALLET::request& req, rpc::COMMAND_RPC_SET_WALLET::response& res, epee::json_rpc::error& er, connection_context& cntx);
	    bool on_create_wallet(const rpc::COMMAND_RPC_CREATE_WALLET::request& req, rpc::COMMAND_RPC_CREATE_WALLET::response& res, epee::json_rpc::error & er, rpc_server::connection_context & cntx);
      bool on_getbalance(const rpc::COMMAND_RPC_GET_BALANCE::request& req, rpc::COMMAND_RPC_GET_BALANCE::response& res, epee::json_rpc::error& er, rpc_server::connection_context& cntx);
      bool on_refresh(const rpc::COMMAND_RPC_REFRESH::request& req, rpc::COMMAND_RPC_REFRESH::response& res, epee::json_rpc::error& er, rpc_server::connection_context& cntx);
      // bool on_getaddress(const rpc::COMMAND_RPC_GET_ADDRESS::request& req, rpc::COMMAND_RPC_GET_ADDRESS::response& res, epee::json_rpc::error& er, connection_context& cntx);
      // bool validate_transfer(const std::list<rpc::transfer_destination> destinations, const std::string payment_id, std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t>& extra, epee::json_rpc::error& er);
      // bool on_transfer(const rpc::COMMAND_RPC_TRANSFER::request& req, rpc::COMMAND_RPC_TRANSFER::response& res, epee::json_rpc::error& er, connection_context& cntx);
      // bool on_transfer_split(const rpc::COMMAND_RPC_TRANSFER_SPLIT::request& req, rpc::COMMAND_RPC_TRANSFER_SPLIT::response& res, epee::json_rpc::error& er, connection_context& cntx);
      // bool on_store(const rpc::COMMAND_RPC_STORE::request& req, rpc::COMMAND_RPC_STORE::response& res, epee::json_rpc::error& er, connection_context& cntx);
      // bool on_get_payments(const rpc::COMMAND_RPC_GET_PAYMENTS::request& req, rpc::COMMAND_RPC_GET_PAYMENTS::response& res, epee::json_rpc::error& er, connection_context& cntx);
      // bool on_get_bulk_payments(const rpc::COMMAND_RPC_GET_BULK_PAYMENTS::request& req, rpc::COMMAND_RPC_GET_BULK_PAYMENTS::response& res, epee::json_rpc::error& er, connection_context& cntx);
      // bool on_incoming_transfers(const rpc::COMMAND_RPC_INCOMING_TRANSFERS::request& req, rpc::COMMAND_RPC_INCOMING_TRANSFERS::response& res, epee::json_rpc::error& er, connection_context& cntx);

      bool handle_command_line(const boost::program_options::variables_map& vm);

      bool create_wallet_from_seed(tools::wallet2* m_wallet, std::string seed, uint64_t account_create_time, uint64_t local_bc_height, std::string transfers);

      //json rpc v2
      //bool on_query_key(const rpc::COMMAND_RPC_QUERY_KEY::request& req, rpc::COMMAND_RPC_QUERY_KEY::response& res, epee::json_rpc::error& er, connection_context& cntx);

      // tools::wallet2& m_wallet;
      std::string m_port;
      std::string m_bind_ip;
	    std::string m_daemon_address;
      epee::net_utils::http::http_simple_client m_http_client;
  };
}
