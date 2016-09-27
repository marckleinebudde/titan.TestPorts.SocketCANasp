/******************************************************************************
 * Copyright (c) 2010, 2016  Ericsson AB
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 * Michel Josenhans
 ******************************************************************************/
//
//  File:               SocketCAN_PT.hh
//  Description:        SocketCAN test port header
#ifndef SocketCAN__PT_HH
#define SocketCAN__PT_HH

#include <TTCN3.hh>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "linux/can.h"
#include "SocketCAN_Types.hh"

// Note: Header file SocketCAN_PortType.hh must not be included into this file!
// (because it includes this file)
// Please add the declarations of message types manually.
namespace SocketCAN__Types {
class SocketCAN;
}

namespace SocketCAN__PortType {

class SocketCAN__PT_PROVIDER: public PORT {
public:
	SocketCAN__PT_PROVIDER(const char *par_port_name = NULL);
	~SocketCAN__PT_PROVIDER();

	void set_parameter(const char *parameter_name, const char *parameter_value);

private:
	/* void Handle_Fd_Event(int fd, boolean is_readable,
	 boolean is_writable, boolean is_error); */
	void Handle_Fd_Event_Error(int fd);
	void Handle_Fd_Event_Writable(int fd);
	void Handle_Fd_Event_Readable(int fd);
	/* void Handle_Timeout(double time_since_last_call); */
protected:
	void user_map(const char *system_port);
	void user_unmap(const char *system_port);

	void user_start();
	void user_stop();

	void outgoing_send(const SocketCAN__Types::SocketCAN__socket& send_par);
	void outgoing_send(const SocketCAN__Types::SocketCAN__ioctl& send_par);
	void outgoing_send(const SocketCAN__Types::SocketCAN__connect& send_par);
	void outgoing_send(const SocketCAN__Types::SocketCAN__bind& send_par);
	void outgoing_send(const SocketCAN__Types::SocketCAN__send__data& send_par);
	void outgoing_send(
			const SocketCAN__Types::SocketCAN__write__data& send_par);
	void outgoing_send(const SocketCAN__Types::SocketCAN__setsockopt& send_par);
	void outgoing_send(const SocketCAN__Types::SocketCAN__close& send_par);
	virtual void incoming_message(
			const SocketCAN__Types::SocketCAN__socket__result& incoming_par) = 0;
	virtual void incoming_message(
			const SocketCAN__Types::SocketCAN__ioctl__result& incoming_par) = 0;
	virtual void incoming_message(
			const SocketCAN__Types::SocketCAN__connect__result& incoming_par) = 0;
	virtual void incoming_message(
			const SocketCAN__Types::SocketCAN__bind__result& incoming_par) = 0;
	virtual void incoming_message(
			const SocketCAN__Types::SocketCAN__send__data__result& incoming_par) = 0;
	virtual void incoming_message(
			const SocketCAN__Types::SocketCAN__write__data__result& incoming_par) = 0;
	virtual void incoming_message(
			const SocketCAN__Types::SocketCAN__receive__CAN__or__CAN__FD__frame& incoming_par) = 0;
	virtual void incoming_message(
			const SocketCAN__Types::SocketCAN__receive__BCM__message& incoming_par) = 0;
	virtual void incoming_message(
			const SocketCAN__Types::SocketCAN__setsockopt__result& incoming_par) = 0;
        void set_asp_params();
        void reset_configuration();
	void InitStrPar(char *&par, const char *name, const char *val);
	void log(const char *fmt, ...);
	void logOctet(const char *prompt, const OCTETSTRING& msg);
	void logHex(const char *prompt, const HEXSTRING& msg);
	void logInteger(const char *prompt, const int number);
	void logBitstring(const char *prompt, const BITSTRING& msg);
	void setUpSocket();
	void closeDownSocket();

private:
	enum socket_allocation_enum {
		SOCKET_NOT_ALLOCATED = 0, SOCKET_OPEN = 1
	};
	enum socket_protocol_family_enum {
		SOCKET_NO_PROTOCOL = 0,
		SOCKET_PROTOCOL_CAN_BCM = 1,
		SOCKET_PROTOCOL_CAN_RAW = 2
	};

	struct sock_data {
		int fd;
		SocketCAN__PortType::SocketCAN__PT_PROVIDER::socket_allocation_enum status;
		SocketCAN__PortType::SocketCAN__PT_PROVIDER::socket_protocol_family_enum protocol_family;
		struct sockaddr_can remote_Addr;
	};

	sock_data *sock_list;
	int num_of_sock;
	int sock_list_length;

	int target_fd;
	// test port parameters
	char* can_interface_name;
	bool debugging;
	bool debugging_configured;
	bool config_finished;
};

} /* end of namespace */

#endif
