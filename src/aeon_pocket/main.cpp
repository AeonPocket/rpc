#include <stdio.h>
#include <string>
#include <thread>
#include <iostream>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include "include_base_utils.h"
#include "common/command_line.h"
#include "common/util.h"
#include "p2p/net_node.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "web_wallet.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "storages/http_abstract_invoke.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc_server.h"
#include "version.h"
#include "crypto/crypto.h"  // for crypto::secret_key definition
#include "crypto/electrum-words.h"
int main(int argc, char** argv)
{
	std::string host_ip = "127.0.0.1";
	std::string host_port = "11191";
	std::string daemon_ip = "127.0.0.1";
	std::string daemon_port= "11181";
	aeon_pocket::rpc_server wrpc;
	std::string daemon_address = std::string("http://") + daemon_ip + ":" + daemon_port;
	bool r = wrpc.init2(host_ip,host_port);
	wrpc.set_daemon_address(daemon_address);
	CHECK_AND_ASSERT_MES(r, 1, "Failed to initialize wallet rpc server");
	LOG_PRINT_L0("Starting wallet rpc server");
	wrpc.run();
	return 1;
}