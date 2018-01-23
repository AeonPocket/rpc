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


class message_writer
{
public:
	message_writer(epee::log_space::console_colors color = epee::log_space::console_color_default, bool bright = false,
				   std::string&& prefix = std::string(), int log_level = LOG_LEVEL_2)
			: m_flush(true)
			, m_color(color)
			, m_bright(bright)
			, m_log_level(log_level)
	{
		m_oss << prefix;
	}

	message_writer(message_writer&& rhs)
			: m_flush(std::move(rhs.m_flush))
#if defined(_MSC_VER)
			, m_oss(std::move(rhs.m_oss))
#else
			// GCC bug: http://gcc.gnu.org/bugzilla/show_bug.cgi?id=54316
			, m_oss(rhs.m_oss.str(), std::ios_base::out | std::ios_base::ate)
#endif
			, m_color(std::move(rhs.m_color))
			, m_log_level(std::move(rhs.m_log_level))
	{
		rhs.m_flush = false;
	}

	template<typename T>
	std::ostream& operator<<(const T& val)
	{
		m_oss << val;
		return m_oss;
	}

	~message_writer()
	{
		if (m_flush)
		{
			m_flush = false;

			LOG_PRINT(m_oss.str(), m_log_level)

			if (epee::log_space::console_color_default == m_color)
			{
				std::cout << m_oss.str();
			}
			else
			{
				epee::log_space::set_console_color(m_color, m_bright);
				std::cout << m_oss.str();
				epee::log_space::reset_console_color();
			}
			std::cout << std::endl;
		}
	}

private:
	message_writer(message_writer& rhs);
	message_writer& operator=(message_writer& rhs);
	message_writer& operator=(message_writer&& rhs);

private:
	bool m_flush;
	std::stringstream m_oss;
	epee::log_space::console_colors m_color;
	bool m_bright;
	int m_log_level;
};

int main(int argc, char** argv)
{
	std::string host_ip = "127.0.0.1";
	std::string host_port = "11191";
	std::string daemon_ip = "127.0.0.1";
	std::string daemon_port= "11181";

	if (argc == 5) {
		host_ip = argv[1];
		host_port = argv[2];
		daemon_ip = argv[3];
		daemon_port = argv[4];
	}
	else {
		std::cout << "Invalid number of Parameters!" << std::endl
			<< "Usage: aeon_pocket host_ip host_port daemon_ip daemon_port" << std::endl
			<< "Using default values" << std::endl;

	}
	std::cout << "host_ip: " << host_ip << std::endl
						<< "host_port: " << host_port<<std::endl
						<< "daemon_ip: " << daemon_ip<<std::endl
						<< "daemon_port: " << daemon_port<<std::endl;

	epee::log_space::log_singletone::get_set_log_detalisation_level(true, 4);
    epee::log_space::log_singletone::add_logger(LOGGER_CONSOLE, NULL, NULL, LOG_LEVEL_4);
	aeon_pocket::rpc_server wrpc;
		std::string daemon_address = std::string("http://") + daemon_ip + ":" + daemon_port;
		bool r = wrpc.init2(host_ip, host_port);
		wrpc.set_daemon_address(daemon_address);
		CHECK_AND_ASSERT_MES(r, 1, "Failed to initialize wallet rpc server");
		LOG_PRINT_L4("Starting wallet rpc server");
		wrpc.run();
		return 0;
	
	return 1;
}