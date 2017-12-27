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
        MAP_JON_RPC_WE("set_wallet",         on_set_wallet,         rpc::COMMAND_RPC_SET_WALLET)
        MAP_JON_RPC_WE("getbalance",         on_getbalance,         rpc::COMMAND_RPC_GET_BALANCE)
        MAP_JON_RPC_WE("refresh",            on_refresh,            rpc::COMMAND_RPC_REFRESH)
        MAP_JON_RPC_WE("transfer",           on_transfer,           rpc::COMMAND_RPC_TRANSFER)
        MAP_JON_RPC_WE("get_transaction",    on_get_transaction,    rpc::COMMAND_RPC_TRANSACTION_FULL)
        MAP_JON_RPC_WE("incoming_transfers", on_incoming_transfers, rpc::COMMAND_RPC_INCOMING_TRANSFERS)
        MAP_JON_RPC_WE("bc_height",          get_blockchain_height, rpc::COMMAND_BC_HEIGHT)
      END_JSON_RPC_MAP()
    END_URI_MAP2()

      //json_rpc
      bool on_set_wallet(const rpc::COMMAND_RPC_SET_WALLET::request& req, rpc::COMMAND_RPC_SET_WALLET::response& res, epee::json_rpc::error& er, connection_context& cntx);
	  bool on_getbalance(const rpc::COMMAND_RPC_GET_BALANCE::request& req, rpc::COMMAND_RPC_GET_BALANCE::response& res, epee::json_rpc::error& er, rpc_server::connection_context& cntx);
      bool on_refresh(const rpc::COMMAND_RPC_REFRESH::request& req, rpc::COMMAND_RPC_REFRESH::response& res, epee::json_rpc::error& er, rpc_server::connection_context& cntx);
      bool validate_transfer(const std::list<rpc::transfer_destination> destinations, const std::string payment_id, std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t>& extra, epee::json_rpc::error& er);
      bool on_transfer(const rpc::COMMAND_RPC_TRANSFER::request& req, rpc::COMMAND_RPC_TRANSFER::response& res, epee::json_rpc::error& er, connection_context& cntx);
      bool on_get_transaction(const rpc::COMMAND_RPC_TRANSACTION_FULL::request& req, rpc::COMMAND_RPC_TRANSACTION_FULL::response& res, epee::json_rpc::error& er, connection_context& cntx);
      bool on_incoming_transfers(const rpc::COMMAND_RPC_INCOMING_TRANSFERS::request& req, rpc::COMMAND_RPC_INCOMING_TRANSFERS::response& res, epee::json_rpc::error& er, connection_context& cntx);

      bool handle_command_line(const boost::program_options::variables_map& vm);

      bool create_wallet_from_keys(tools::wallet2* m_wallet, std::string address, std::string view_key, uint64_t account_create_time, uint64_t local_bc_height, std::string transfers, std::string key_images);
      
      uint64_t get_daemon_blockchain_height(std::string& err);
      bool get_blockchain_height(const rpc::COMMAND_BC_HEIGHT::request& req, rpc::COMMAND_BC_HEIGHT::response& res, epee::json_rpc::error& er, connection_context& cntx);

      inline std::string interpret_rpc_response(bool ok, const std::string& status)
      {
        std::string err;
        if (ok)
        {
          if (status == CORE_RPC_STATUS_BUSY)
          {
            err = "daemon is busy. Please try later";
          }
          else if (status != CORE_RPC_STATUS_OK)
          {
            err = status;
          }
        }
        else
        {
          err = "possible lost connection to daemon";
        }
        return err;
      }
      //json rpc v2
      //bool on_query_key(const rpc::COMMAND_RPC_QUERY_KEY::request& req, rpc::COMMAND_RPC_QUERY_KEY::response& res, epee::json_rpc::error& er, connection_context& cntx);

      // tools::wallet2& m_wallet;
      std::string m_port;
      std::string m_bind_ip;
	    std::string m_daemon_address;
      epee::net_utils::http::http_simple_client m_http_client;
  };
}
