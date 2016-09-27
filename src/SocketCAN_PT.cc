/******************************************************************************
 * Copyright (c) 2010, 2016  Ericsson AB
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 * Michael Josenhans
 ******************************************************************************/
//
//  File:               SocketCAN_PT.cc
//  Description:        SocketCAN_PT test port source
//
// Revision R1A
#include "SocketCAN_PT.hh"

#include <Addfunc.hh>
#include <Bitstring.hh>
#include <Charstring.hh>
#include <errno.h>
#include <Error.hh>
#include <Hexstring.hh>
#include <Integer.hh>
#include <linux/can/bcm.h>
#include <linux/can/raw.h>
#include <linux/if.h>
#include <Logger.hh>
#include <memory.h>
#include <Octetstring.hh>
#include <Optional.hh>
#include <Port.hh>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <Template.hh>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstring>
#include <iostream>

struct bcm_msg_head;
struct can_frame;
struct canfd_frame;

#define DEFAULT_NUM_SOCK          10
#define BCM_FRAME_BUFFER_SIZE    256
#define BCM_FRAME_FLAGS_SIZE      32 // size of SocketCAN_bcm_frame in Bit

// workaround, as some of those below may not yet be defined in "linux/can/raw.h":
#define CAN_RAW_FILTER            1 /* set 0 .. n can_filter(s)          */
#define CAN_RAW_ERR_FILTER        2 /* set filter for error frames       */
#define CAN_RAW_LOOPBACK          3 /* local loopback (default:on)       */
#define CAN_RAW_RECV_OWN_MSGS     4 /* receive my own msgs (default:off) */
#define CAN_RAW_FD_FRAMES         5 /* allow CAN FD frames (default:off) */
#define CAN_RAW_JOIN_FILTERS      6 /* all filters must match to trigger */



// workaround, as not yet defined in all versions of "linux/Can.h":
#ifndef CAN_MAX_DLEN
#define CAN_MAX_DLEN 8
#endif

// workaround, as not defined in some older kernel versions
#ifndef	CAN_MTU
#define CAN_MTU		(sizeof(struct can_frame))
#endif  //CANFD_MTU

// workaround, as canfd not defined in some older kernel versions
// and thus canfd frames can not be used for data transfer between 
// kernel module and userspace.
#ifdef	CANFD_MTU
#define CANFD_FRAME_STRUCT_DEFINED             true
#define RAW_CANFD_SUPPORT                      true
#endif  //CANFD_MTU

// has to be defined in later kernel versions in bcm.h as #define CAN_FD_FRAME   0x0800
#ifdef  CAN_FD_FRAME
#define BCM_CANFD_SUPPORT                      true
#endif

namespace SocketCAN__PortType {

SocketCAN__PT_PROVIDER::SocketCAN__PT_PROVIDER(const char *par_port_name) :
		PORT(par_port_name), num_of_sock(0), sock_list_length(0), target_fd(-1), can_interface_name(
		NULL), debugging(false), debugging_configured(false), config_finished(
				false) {
	sock_list = NULL;
	//&num_of_sock = 0;
	//sock_list_length = 0;
}

SocketCAN__PT_PROVIDER::~SocketCAN__PT_PROVIDER() {
	Free(sock_list);
	reset_configuration();
}

void SocketCAN__PT_PROVIDER::set_parameter(const char * parameter_name,
		const char * parameter_value) {
	log("entering SocketCAN__PT_PROVIDER::set_parameter(%s, %s)",
			parameter_name, parameter_value);

	if (config_finished) {
		reset_configuration();
		config_finished = false;
	}

	if (strcmp(parameter_name, "SocketCAN_can_interface_name") == 0) {
		InitStrPar(can_interface_name, parameter_name, parameter_value);
	} else if (strcmp(parameter_name, "SocketCAN_debugging") == 0) {
		if (strcmp(parameter_value, "YES") == 0) {
			debugging = true;
			debugging_configured = true;
			log("Reading testport parameter debugging: ", debugging);
		} else if (strcmp(parameter_value, "NO") == 0) {
			debugging = false;
			debugging_configured = true;
			log("Reading testport parameter debugging: ", debugging);
		}
	} else {
		TTCN_error(
				"SocketCAN parameter configuration error: Configuration file does not correctly configure parameter 'SocketCAN_debugging' however parameter name '%s' as parameter value: '%s'!!\nExpecting: \n*.*.SocketCAN_debugging := \"YES\"\n or \n*.*.SocketCAN_debugging := \"NO\"",
				parameter_name, parameter_value);
	}

	log("leaving SocketCAN__PT_PROVIDER::set_parameter(%s, %s)", parameter_name,
			parameter_value);
}

/*void SocketCAN__PT_PROVIDER::Handle_Fd_Event(int fd, boolean is_readable,
 boolean is_writable, boolean is_error) {}*/

void SocketCAN__PT_PROVIDER::Handle_Fd_Event_Error(int /*fd*/) {

}

void SocketCAN__PT_PROVIDER::Handle_Fd_Event_Writable(int /*fd*/) {

}

void SocketCAN__PT_PROVIDER::Handle_Fd_Event_Readable(int sock) {
	log("entering SocketCAN__PT_PROVIDER::Handle_Fd_Event_Readable()");
	int res;

	for (int a = 0; a < sock_list_length; a++) {
		if ((sock == sock_list[a].fd)
				and (sock_list[a].status != SOCKET_NOT_ALLOCATED)) {
			switch (sock_list[a].protocol_family) {
			case SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_PROTOCOL_CAN_RAW: {
				SocketCAN__Types::SocketCAN__receive__CAN__or__CAN__FD__frame parameters;

				struct sockaddr_can addr;
				socklen_t addr_len = sizeof(addr);
				//ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
				// struct sockaddr *src_addr, socklen_t *addrlen);
#ifdef	CANFD_FRAME_STRUCT_DEFINED   // struct canfd_frame is supported
				struct canfd_frame frame; // always asume a CANFD_Frame shall be received
				ssize_t nbytes = recvfrom(sock, &frame, CANFD_MTU, 0,
						(struct sockaddr*) &addr, &addr_len);
#else   //CANFD_FRAME_STRUCT_DEFINED
				struct can_frame frame; // CANFD_Frame is not supported by this kernel version
				ssize_t nbytes = recvfrom(sock, &frame, CAN_MTU, 0,
						(struct sockaddr*) &addr, &addr_len);
#endif  //CANFD_FRAME_STRUCT_DEFINED

				if (nbytes <= 0) {
					//there is an empty message, or error in receive
					//remove the socket
					TTCN_error(
							"Closing socket %d with interface index %d due to an empty message or error in reception\n",
							sock, addr.can_ifindex);
					std::cout << "close_fd" << sock << std::endl;
					sock_list[a].status = SOCKET_NOT_ALLOCATED;
					sock_list[a].protocol_family =
							SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_NO_PROTOCOL;
					num_of_sock--;
					Handler_Remove_Fd_Read(sock);
					close(sock);
				} else

				if ((nbytes == CAN_MTU) 
#ifdef	CANFD_FRAME_STRUCT_DEFINED
                                    or (nbytes == CANFD_MTU)
#endif  //CANFD_FRAME_STRUCT_DEFINED
                                ){
					// A CAN Frame has been received. However use the struct canfd_frame to access it.
					// As it is a CAN frame, the flags field contains invalid data and the can_dlc field
					// is here called len as in CAN FD.
					struct ifreq ifr;
					ifr.ifr_ifindex = addr.can_ifindex;
					/* get interface name of the received CAN frame */
					res = ioctl(sock, SIOCGIFNAME, &ifr);
					if (res != 0) {
						TTCN_error(
								"SocketCAN frame reception: Ioctl failed while retrieving the interface name from the socket: %d with interface index %d\n",
								sock, ifr.ifr_ifindex);
#ifdef	CANFD_FRAME_STRUCT_DEFINED
						log("SocketCAN: Received a CAN frame from interface %s",
								ifr.ifr_name, nbytes, frame.len);
#else   //CANFD_FRAME_STRUCT_DEFINED
						log("SocketCAN: Received a CAN frame from interface %s",
								ifr.ifr_name, nbytes, frame.can_dlc);
#endif  //CANFD_FRAME_STRUCT_DEFINED
						parameters.ifr().if__index() = ifr.ifr_ifindex;
						parameters.ifr().if__name() =
								"SocketCAN : device name unknown, ioctl failed";
					} else {
						parameters.ifr().if__index() = ifr.ifr_ifindex;
						parameters.ifr().if__name() =
								"SocketCAN : device name unknown, ioctl failed";
						parameters.ifr().if__name() = ifr.ifr_name;
					}

					struct timeval tv;
					res = ioctl(sock, SIOCGSTAMP, &tv);
					if (res != 0) {
						TTCN_error(
								"SocketCAN frame reception: Ioctl failed while retrieving the timestamp from the socket: %d with interface name %s\n",
								sock, ifr.ifr_name);

					} else {
						parameters.timestamp().tv__sec() = tv.tv_sec;
						parameters.timestamp().tv__usec() = tv.tv_usec;
					}
					parameters.ifr().if__index() = ifr.ifr_ifindex;
					parameters.ifr().if__name() = ifr.ifr_name;
					parameters.id() = a;

					const INTEGER can_id = frame.can_id;
#ifdef CANFD_FRAME_STRUCT_DEFINED
					const INTEGER len = frame.len;
#else  //CANFD_FRAME_STRUCT_DEFINED
                    const INTEGER len = frame.can_dlc;
#endif //CANFD_FRAME_STRUCT_DEFINED
					// frame type specific part:
					if (nbytes == CAN_MTU) {
						// CAN frame received:
						Can::CAN__frame& frameref =
								parameters.frame().can__frame();
						log(
								"Received a CAN frame from interface %s of %d bytes and with payload length %d",
								ifr.ifr_name, nbytes, (int)len);
						parameters.ifr().if__index() = ifr.ifr_ifindex;
						parameters.ifr().if__name() = ifr.ifr_name;
						parameters.id() = a;
						frameref.can__id() = frame.can_id;
						frameref.can__pdu() = OCTETSTRING(len, frame.data);
					} else {
						// CAN FD frame received:
						Can::CANFD__frame& frameref =
								parameters.frame().canfd__frame();
						log(
								"Received a CAN FD frame from interface %s of %d bytes and with payload length %d",
								ifr.ifr_name, nbytes, len);
						frameref.can__id() = can_id;
#ifdef CANFD_FRAME_STRUCT_DEFINED
						frameref.can__flags() = BITSTRING(
								int2bit(frame.flags,
										frameref.can__flags().lengthof()));
#endif //CANFD_FRAME_STRUCT_DEFINED
						frameref.can__pdu() = OCTETSTRING(len, frame.data);
					}
					incoming_message(parameters);
				}
			}
				break;
			case SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_PROTOCOL_CAN_BCM: {
				SocketCAN__Types::SocketCAN__receive__BCM__message parameters;
				struct sockaddr_can addr;
				struct {
					struct bcm_msg_head msg_head;
#ifdef CANFD_FRAME_STRUCT_DEFINED
					struct canfd_frame frame[BCM_FRAME_BUFFER_SIZE];
#else  //CANFD_FRAME_STRUCT_DEFINED
					struct can_frame frame[BCM_FRAME_BUFFER_SIZE];
#endif //CANFD_FRAME_STRUCT_DEFINED
				} bcm_msg;
				struct ifreq ifr;

				socklen_t addr_len = sizeof(addr);
				ssize_t nbytes = recvfrom(sock, &bcm_msg,
						sizeof(struct can_frame), 0, (struct sockaddr*) &addr,
						&addr_len);
				if (nbytes < 0) {
					//there is an empty message, or error in receive
					//remove the socket
					TTCN_error(
							"Closing socket %d with interface index %d due to an empty BCM message or error in reception\n",
							sock, addr.can_ifindex);
					std::cout << "close_fd" << sock << std::endl;
					sock_list[a].status = SOCKET_NOT_ALLOCATED;
					sock_list[a].protocol_family =
							SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_NO_PROTOCOL;
					num_of_sock--;
					Handler_Remove_Fd_Read(sock);
					close(sock);
				} else {
					ifr.ifr_ifindex = addr.can_ifindex;
					// get interface name of the received CAN frame

					// currently handling of can_ifindex == 0 (= any interface) is unclear.
//					res = ioctl(sock, SIOCGIFNAME, &ifr);
//					if (res == -1) {
//						TTCN_error(
//								"Ioctl failed while receiving a BCM message frame on socket: %d with interface index %d with errno: %d\n",
//								sock, ifr.ifr_ifindex, errno);
//					}
					const INTEGER msg_head_flags = bcm_msg.msg_head.flags;
					log(
							"Received a BCM message from interface index %d of bytes %d",
							ifr.ifr_ifindex, nbytes);
					parameters.id() = bcm_msg.msg_head.can_id;
					parameters.ifr().if__index() = ifr.ifr_ifindex;
					parameters.ifr().if__name() = ifr.ifr_name;

					uint32_t nframes = bcm_msg.msg_head.nframes;
					parameters.frame().opcode() = bcm_msg.msg_head.opcode;
					parameters.frame().flags() = BITSTRING(
							int2bit(INTEGER(msg_head_flags),
									BCM_FRAME_FLAGS_SIZE));
					parameters.frame().count() = bcm_msg.msg_head.count;
					parameters.frame().ival1().tv__sec() =
							bcm_msg.msg_head.ival1.tv_sec;
					parameters.frame().ival1().tv__usec() =
							bcm_msg.msg_head.ival1.tv_usec;
					parameters.frame().ival2().tv__sec() =
							bcm_msg.msg_head.ival2.tv_sec;
					parameters.frame().ival2().tv__usec() =
							bcm_msg.msg_head.ival2.tv_usec;
					parameters.frame().can__id() = bcm_msg.msg_head.can_id;
#ifdef BCM_CANFD_SUPPORT
					long flags = bcm_msg.msg_head.flags;
					if ((flags & CAN_FD_FRAME ) == CAN_FD_FRAME ) {
						// Handle CAN FD frames

						parameters.frame().frames().can__frame().set_size(nframes);
						for (uint32_t i = 0; i < nframes; i++) {
							INTEGER len;
							len = bcm_msg.frame[i].len;
							if (len > CANFD_MAX_DLEN) {
								TTCN_error("Writing data: CAN FD pdu size too large\n");
							};
							parameters.frame().frames().canfd__frame()[i].can__id() =
							bcm_msg.frame[i].can_id;
							//Here the bitstring shall be stored into a
							parameters.frame().frames().canfd__frame()[i].can__flags() =
							BITSTRING(32,
									(const unsigned char*) &(bcm_msg.frame[i].flags));
							parameters.frame().frames().canfd__frame()[i].can__pdu() =
							OCTETSTRING(len,
									(const unsigned char*) &(bcm_msg.frame[i].data));
						}
						incoming_message(parameters);
					}
					else
#endif //BCM_CANFD_SUPPORT
					{
						parameters.frame().frames().can__frame().set_size(
								nframes);
						for (uint32_t i = 0; i < nframes; i++) {
							INTEGER len;
#ifdef	CANFD_FRAME_STRUCT_DEFINED   // struct canfd_frame is supported
							len = bcm_msg.frame[i].len;
#else   //CANFD_FRAME_STRUCT_DEFINED   // struct canfd_frame is supported
							len = bcm_msg.frame[i].can_dlc;
#endif	//CANFD_FRAME_STRUCT_DEFINED   // struct canfd_frame is supported
							// Handle legacy CAN frames
							if (len > CAN_MAX_DLEN) {
								TTCN_error("Writing data: CAN pdu size too large\n");
								len = CAN_MAX_DLEN;
							};
							parameters.frame().frames().can__frame()[i].can__id() =
									bcm_msg.frame[i].can_id;
							parameters.frame().frames().can__frame()[i].can__pdu() =
									OCTETSTRING(len,
											(const unsigned char*) &(bcm_msg.frame[i].data));

						}
						incoming_message(parameters);
					}
				}
			}
				break;
			default: {
				TTCN_error(
						"SocketCAN Handle_Fd_Event_Readable (%d): unhandled protocol configured",
						sock);
			}
				break;
			}
		}
	}
	log("leaving SocketCAN__PT_PROVIDER::Handle_Fd_Event_Readable()");
}

void SocketCAN__PT_PROVIDER::user_map(const char */*system_port */) {
	log("entering SocketCAN__PT_PROVIDER::user_map()");

	config_finished = true;

	if (debugging_configured == false) {
		// The debugging mode has not been defined in TTCN configuration file.
		TTCN_error(
				"Missing mandatory parameter: SocketCAN_debuhhing for can_interface_name %s \n",
				can_interface_name);
	}

	if (sock_list != NULL)
		TTCN_error("SocketCAN Test Port (%s): Internal error: "
				"sock_list is not NULL when mapping.", port_name);
	sock_list = (sock_data*) Malloc(DEFAULT_NUM_SOCK * sizeof(*sock_list));
	num_of_sock = 0;
	sock_list_length = DEFAULT_NUM_SOCK;
	for (int a = 0; a < sock_list_length; a++) {
		sock_list[a].status = SOCKET_NOT_ALLOCATED;
		sock_list[a].protocol_family =
				SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_NO_PROTOCOL;
	}

	log("leaving SocketCAN__PT_PROVIDER::user_map()");
}

void SocketCAN__PT_PROVIDER::user_unmap(const char * /*system_port*/) {
	log("entering SocketCAN__PT_PROVIDER::user_unmap()");

	closeDownSocket();

	log("leaving SocketCAN__PT_PROVIDER::user_unmap()");
}

void SocketCAN__PT_PROVIDER::user_start() {

}

void SocketCAN__PT_PROVIDER::user_stop() {

}

void SocketCAN__PT_PROVIDER::outgoing_send(
		const SocketCAN__Types::SocketCAN__socket& send_par) {
	log("entering SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__socket)");
	int cn;
	SocketCAN__Types::SocketCAN__socket__result result;

	if (num_of_sock < sock_list_length) {
		cn = 0;
		while (sock_list[cn].status == SOCKET_OPEN) {
			cn++;
		}
	} else {
		sock_list = (sock_data*) Realloc(sock_list,
				2 * sock_list_length * sizeof(*sock_list));
		for (int a = sock_list_length; a < sock_list_length * 2; a++) {
			sock_list[a].status = SOCKET_NOT_ALLOCATED;
		}
		cn = sock_list_length;
		sock_list_length *= 2;
	}

	//extern int socket (int __domain, int __type, int __protocol) __THROW;
	target_fd = socket(send_par.domain(), send_par.ptype(),
			send_par.protocol());
	if (target_fd <= 0) {
		TTCN_error("Cannot open socket \n");
		result.result().result__code() =
				SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
		result.result().err() = errno;
		result.result().err__text() = "Cannot open socket";
	} else {
		log("SocketCAN opened socket %d \n", target_fd);
		sock_list[cn].fd = target_fd;
		sock_list[cn].status = SOCKET_OPEN;

		num_of_sock++;

		//Handler_Add_Fd_Read(target_fd);

		result.id() = cn;
		result.result().result__code() =
				SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
		result.result().err() = OMIT_VALUE;
		result.result().err__text() = OMIT_VALUE;
	}

	incoming_message(result);
	log("leaving SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__socket)");
}

void SocketCAN__PT_PROVIDER::outgoing_send(
		const SocketCAN__Types::SocketCAN__ioctl& send_par) {
	log("entering SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__ioctl)");

	struct ifreq ifr;

	int sock;
	int cn = send_par.id();
	int res;
	SocketCAN__Types::SocketCAN__ioctl__result result;

	if ((cn < sock_list_length) and (sock_list[cn].status == SOCKET_OPEN)) {
		sock = sock_list[cn].fd;
		if (send_par.ifu().is_present()) {
			const OPTIONAL<SocketCAN__Types::SocketCAN__ioctl__ifu>& ifu =
					send_par.ifu();
			switch (ifu().get_selection()) {
			case SocketCAN__Types::SocketCAN__ioctl__ifu::ALT_if__name:
				strcpy(ifr.ifr_name, ifu().if__name());
				res = ioctl(sock, SIOCGIFINDEX, &ifr);
				if (res != 0) {
					TTCN_error(
							"Ioctl failed on socket: %d with interface name %s\n",
							sock, (const char *) ifu().if__name());
					result.ifr().if__name() = ifu().if__name();
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
					result.result().err() = errno;
					result.result().err__text() = "Ioctl failed";

				} else {
					log("SocketCAN ioctl successful on socket %d \n", sock);
					result.ifr().if__name() = ifu().if__name();
					result.ifr().if__index() = ifr.ifr_ifindex;
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
					result.result().err() = OMIT_VALUE;
					result.result().err__text() = OMIT_VALUE;
				}

				break;
			case SocketCAN__Types::SocketCAN__ioctl__ifu::ALT_if__index:
				res = ioctl(sock, SIOCGIFNAME, &ifr);
				if (res != 0) {
					TTCN_error(
							"Ioctl failed on socket: %d with interface index %llu \n",
							sock, ifu().if__index().get_long_long_val());
					result.ifr().if__index() = ifr.ifr_ifindex;
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
					result.result().err() = errno;
					result.result().err__text() = "Ioctl failed";
				} else {
					log("SocketCAN ioctl successful on socket %d \n", sock);
					result.ifr().if__name() = ifr.ifr_name;
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
					result.result().err() = OMIT_VALUE;
					result.result().err__text() = OMIT_VALUE;
				}
				break;
			default:
				TTCN_error("Ioctl failed due to unknown union selection");
				break;
			}
		} else {
			// optional ifu filed is not present, set take interface name from applicable TTCN configuration file
			if (can_interface_name == NULL) {
				TTCN_error(
						"Missing mandatory parameter: \"SocketCAN_can_interface_name\" has not been defined in function call to Send Data nor in test configuration file! ");
			} else {
				strcpy(ifr.ifr_name, can_interface_name);
				res = ioctl(sock, SIOCGIFINDEX, &ifr);
				if (res != 0) {
					TTCN_error(
							"Ioctl failed on socket: %d with interface name %s \n",
							sock, can_interface_name);
					result.ifr().if__index() = ifr.ifr_ifindex;
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
					result.result().err() = errno;
					result.result().err__text() = "Ioctl failed";
				} else {
					log("SocketCAN ioctl successful on socket %d \n", sock);
					result.ifr().if__name() = ifr.ifr_name;
					result.ifr().if__index() = ifr.ifr_ifindex;
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
					result.result().err() = OMIT_VALUE;
					result.result().err__text() = OMIT_VALUE;
				}
				if (strlen(can_interface_name) <= IFNAMSIZ) {
					std::strcpy(ifr.ifr_name, can_interface_name);

				} else {
					TTCN_error(
							"Ioctl failed due to interface name too long.\n");
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
					result.result().err() = OMIT_VALUE;
					result.result().err__text() =
							"Ioctl failed due to interface name too long";
				}
			}
		}
	} else {
		TTCN_error("Ioctl failed due to unknown socket reference: %d \n", cn);
		result.ifr().if__name() = ifr.ifr_name;
		result.result().result__code() =
				SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
		result.result().err() = OMIT_VALUE;
		result.result().err__text() =
				"Ioctl failed due to unknown socket reference";
	}
	incoming_message(result);
	log("SocketCAN__PT::outgoing_send(SocketCAN__ioctl)");
}
void SocketCAN__PT_PROVIDER::outgoing_send(
		const SocketCAN__Types::SocketCAN__connect& send_par) {
//Client connects to BCM
	log("entering SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__connect)");

	int sock;
	struct sockaddr_can addr;
	int cn = send_par.id();
	int res;
	SocketCAN__Types::SocketCAN__connect__result result;

	if ((cn < sock_list_length) and (sock_list[cn].status == SOCKET_OPEN)) {
		if (sock_list[cn].protocol_family
				== SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_NO_PROTOCOL) {
			sock = sock_list[cn].fd;

			addr.can_family = AF_CAN;
			addr.can_ifindex = send_par.if__index();

			//extern int connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);
			res = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
			if (res != 0) {
				TTCN_error("Connecting to socket %d failed: \n", sock);
				log("Connecting to socket %d failed", sock);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = errno;
				result.result().err__text() = "Connecting to socket failed";
			} else {
				log("Connecting socket %d was successful", sock);
				sock_list[cn].protocol_family =
						SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_PROTOCOL_CAN_BCM;
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() = OMIT_VALUE;
				sock_list[cn].remote_Addr.can_family = AF_CAN;
				Handler_Add_Fd_Read(target_fd);
			}
		} else {
			TTCN_error("Socket reference already connected or bound: %d \n",
					cn);
			result.result().result__code() =
					SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
			result.result().err() = OMIT_VALUE;
			result.result().err__text() =
					"Socket reference already connected or bound";
		}
	} else {
		TTCN_error("Unknown socket reference: %d \n", cn);
		result.result().result__code() =
				SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
		result.result().err() = OMIT_VALUE;
		result.result().err__text() = "Unknown socket reference";
	}
	incoming_message(result);
	log("leaving SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__connect)");
}

void SocketCAN__PT_PROVIDER::outgoing_send(
		const SocketCAN__Types::SocketCAN__bind& send_par) {
//Client binds
	log("entering SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__bind)");

	int sock;
	struct sockaddr_can addr;
	int cn = send_par.id();
	int res;
	SocketCAN__Types::SocketCAN__bind__result result;

	if ((cn < sock_list_length) and (sock_list[cn].status == SOCKET_OPEN)) {
		if (sock_list[cn].protocol_family
				== SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_NO_PROTOCOL) {
			int if_index;
			sock = sock_list[cn].fd;

			addr.can_family = AF_CAN;
			if_index = send_par.if__index();
			addr.can_ifindex = if_index;
			log("Binding socket: %d with index: %d", sock, if_index);
			res = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
			if (res != 0) {
				log("Binding to socket %d failed", sock);
				TTCN_error("Binding to socket %d failed:\n", sock);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = errno;
			} else {
				log("Binding socket %d was successful", sock);
				sock_list[cn].protocol_family =
						SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_PROTOCOL_CAN_RAW;
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() = OMIT_VALUE;
				sock_list[cn].remote_Addr.can_family = AF_CAN;
				Handler_Add_Fd_Read(target_fd);
			}
		} else {
			TTCN_error("Socket reference already connected or bound: %d \n",
					cn);
			result.result().result__code() =
					SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
			result.result().err() = errno;
			result.result().err__text() =
					"Socket reference already connected or bound";
		}
	} else {
		TTCN_error("Unknown socket reference: %d \n", cn);
		result.result().result__code() =
				SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
		result.result().err() = OMIT_VALUE;
		result.result().err__text() = "Unknown socket reference";
	}
	incoming_message(result);
	log("leaving SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__bind)");
}

void SocketCAN__PT_PROVIDER::outgoing_send(
		const SocketCAN__Types::SocketCAN__send__data& send_par) {
	log(
			"entering SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__send__data)");

	SocketCAN__Types::SocketCAN__send__data__result result;
	int res = 0;
	int sock;
	int cn = send_par.id();

	if ((cn < sock_list_length)) {
		struct sockaddr_can addr;
		struct ifreq ifr;
		int nrOfBytesSent, nrOfBytestoSend;
		sock = sock_list[cn].fd;

		if (send_par.ifu().is_present()) {
			const OPTIONAL<SocketCAN__Types::SocketCAN__send__data__ifu>& ifu =
					send_par.ifu();
			switch (ifu().get_selection()) {
			case SocketCAN__Types::SocketCAN__send__data__ifu::ALT_if__index:
				addr.can_ifindex = ifu().if__index();
				addr.can_family = AF_CAN;
				break;
			case SocketCAN__Types::SocketCAN__send__data__ifu::ALT_if__name:
				strcpy(ifr.ifr_name, ifu().if__name());
				res = ioctl(sock, SIOCGIFINDEX, &ifr);
				if (res != 0) {
					TTCN_error(
							"SocketCAN: Send CAN frame: Ioctl failed while retrieving the interface : %d with interface index %s\n",
							sock, ifr.ifr_name);
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
					result.result().err() = errno;
					result.result().err__text() =
							"SocketCAN: Send CAN frame: Ioctl failed while retrieving the interface";
				}
				addr.can_ifindex = ifr.ifr_ifindex;
				addr.can_family = AF_CAN;
				break;
			case SocketCAN__Types::SocketCAN__send__data__ifu::ALT_if__any:
				addr.can_ifindex = 0;
				addr.can_family = AF_CAN;
				break;
			default:
				TTCN_error(
						"SocketCAN: Send CAN frame: Unknown union selection");
				res = -1;
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() =
						"SocketCAN: Send CAN frame: Unknown union selection";
			}
		} else {
			// optional ifu filed is not present, thus send to any interface:
			addr.can_ifindex = 0;
			addr.can_family = AF_CAN;
		}

		if (res == 0) { // check if previous interface inquiry step failed
			switch (send_par.frame().get_selection()) {
			case SocketCAN__Types::SocketCAN__CAN__or__CAN__FD__frame::ALT_can__frame: {
				struct can_frame frame;

				log("SocketCAN: Sending CAN frame)");
				logInteger(" to can id: ",
						send_par.frame().can__frame().can__id());
				logOctet("containing data: ",
						send_par.frame().can__frame().can__pdu());

				size_t can_dlc =
						send_par.frame().can__frame().can__pdu().lengthof();
				frame.can_id = send_par.frame().can__frame().can__id();
				memcpy(frame.data, send_par.frame().can__frame().can__pdu(),
						can_dlc);
				frame.can_dlc = can_dlc;

				nrOfBytestoSend = sizeof(frame);
				if (send_par.ifu().is_present()) {
					nrOfBytesSent = sendto(sock, &frame, nrOfBytestoSend, 0,
							(struct sockaddr*) &addr, sizeof(addr));
					if (nrOfBytesSent < 0) {
						log(
								"SocketCAN: Sent CAN frame with sendto of size %d failed",
								nrOfBytesSent);
						TTCN_error(
								"SocketCAN send with sendto() error while trying to send %d bytes",
								nrOfBytestoSend);
						result.result().result__code() =
								SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
						result.result().err() = errno;
						result.result().err__text() =
								"SocketCAN send with sendto() error";
					} else {
						log(
								"SocketCAN send data with sendto() successful on socket %d \n",
								sock);
						result.result().result__code() =
								SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
						result.result().err() = OMIT_VALUE;
						result.result().err__text() = OMIT_VALUE;
					}
				} else {
					nrOfBytesSent = send(sock, &frame, nrOfBytestoSend, 0);
					log("Sent CAN frame with send of size %d", nrOfBytesSent);
					if (nrOfBytesSent < 0) {
						log("Sent CAN frame with send of size %d failed",
								nrOfBytesSent);
						TTCN_error(
								"SocketCAN send with send() error while trying to send CAN frame of %d bytes",
								nrOfBytestoSend);
						result.result().result__code() =
								SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
						result.result().err() = errno;
						result.result().err__text() =
								"SocketCAN send with send() error";
					} else {
						log(
								"SocketCAN send data with send() successful on socket %d \n",
								sock);
						result.result().result__code() =
								SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
						result.result().err() = OMIT_VALUE;
						result.result().err__text() = OMIT_VALUE;
					}
				}
			}
				break;
#ifdef RAW_CANFD_SUPPORT
				case SocketCAN__Types::SocketCAN__CAN__or__CAN__FD__frame::ALT_canfd__frame: {
					struct canfd_frame fd_frame;

					log("SocketCAN: Sending CAN FD frame)");
					logInteger(" to can id: ",
							send_par.frame().canfd__frame().can__id());
					logBitstring("with flags: ",
							send_par.frame().canfd__frame().can__flags());
					logOctet("containing data: ",
							send_par.frame().canfd__frame().can__pdu());

					size_t len =
					send_par.frame().canfd__frame().can__pdu().lengthof();
					fd_frame.can_id = send_par.frame().canfd__frame().can__id();
					memcpy(fd_frame.data,
							send_par.frame().canfd__frame().can__pdu(), len);
					fd_frame.len = len;

					nrOfBytestoSend = sizeof(fd_frame);
					if (send_par.ifu().is_present()) {

						nrOfBytesSent = sendto(sock, &fd_frame, nrOfBytestoSend, 0,
								(struct sockaddr*) &addr, sizeof(addr));
						if (nrOfBytesSent < 0) {
							TTCN_error(
									"SocketCAN FD send with sendto() error while trying to send %d bytes",
									nrOfBytestoSend);
							result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
							result.result().err() = errno;
							result.result().err__text() =
							"SocketCAN FD send with sendto() error";
						} else {
							log(
									"SocketCAN: Sent CAN FD frame with sendto() of size %d",
									nrOfBytesSent);
							result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
							result.result().err() = OMIT_VALUE;
							result.result().err__text() = OMIT_VALUE;
						}
					} else {
						nrOfBytesSent = send(sock, &fd_frame, nrOfBytestoSend, 0);
						if (nrOfBytesSent < 0) {
							TTCN_error(
									"SocketCAN FD send with send() error while trying to send %d bytes",
									nrOfBytestoSend);
							result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
							result.result().err() = errno;
							result.result().err__text() =
							"SocketCAN FD send with send() error";
						} else {
							log(
									"SocketCAN: Sent CAN FD frame with send() of size %d",
									nrOfBytesSent);
							result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
							result.result().err() = OMIT_VALUE;
							result.result().err__text() = OMIT_VALUE;
						}
					}
				}
				break;
#else  // RAW_CANFD_SUPPORT
			case SocketCAN__Types::SocketCAN__CAN__or__CAN__FD__frame::ALT_canfd__frame: {
				TTCN_error(
						"SocketCAN: CAN FD is not supported by your current kernel error");
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() =
						"SocketCAN: CAN FD is not supported by your current kernel error";
			}
				break;
#endif // RAW_CANFD_SUPPORT

			default:
				TTCN_error("SocketCAN send unknown frame type error");
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() =
						"SocketCAN send unknown frame type error";
				break;
			}
			log("SocketCAN: Nr of bytes sent = %d", nrOfBytesSent);
			if ((nrOfBytesSent > 0) and (nrOfBytesSent != nrOfBytestoSend)
					and (nrOfBytestoSend != 0)) {
				TTCN_error(
						"Send system call failed: %d bytes were sent instead of %d",
						nrOfBytesSent, nrOfBytestoSend);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() =
						"SocketCAN write failed as wrong number of bytes have been written";
			}
		}
	} else {
		TTCN_error("SocketCAN: Unknown socket reference: %d \n", cn);
		result.result().result__code() =
				SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
		result.result().err() = OMIT_VALUE;
		result.result().err__text() = "Unknown socket reference";
	}
	incoming_message(result);
	log("leaving SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__send__data)");
}

void SocketCAN__PT_PROVIDER::outgoing_send(
		const SocketCAN__Types::SocketCAN__write__data& send_par) {
	log(
			"entering SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__write__data)");

	SocketCAN__Types::SocketCAN__write__data__result result;
	int sock;
	int cn = send_par.id();

	if ((cn < sock_list_length)
			and (sock_list[cn].protocol_family
					== SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_PROTOCOL_CAN_BCM)
			and (sock_list[cn].status == SOCKET_OPEN)) {
		sock = sock_list[cn].fd;

		switch (send_par.bcm__tx__msg().frames().get_selection()) {
		case Bcm::SocketCAN__bcm__frame_frames::ALT_can__frame: {
			int nrOfBytesSent = 0;
			int nrOfBytestoSend = 0;
			struct {
				struct bcm_msg_head msg_head;
				struct can_frame frame[BCM_FRAME_BUFFER_SIZE];
			} bcm_msg;

			const Bcm::SocketCAN__bcm__frame& bcm__tx__msg =
					send_par.bcm__tx__msg();

			int nframes = bcm__tx__msg.frames().can__frame().lengthof();

			if (nframes > BCM_FRAME_BUFFER_SIZE) {
				TTCN_error(
						"SocketCAN: Writing data: number of CAN frames too large: %d \n",
						nframes);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = errno;
				result.result().err__text() =
						"SocketCAN sending CAN data with write() failed, as more than BCM_FRAME_BUFFER_SIZE number of CAN frames to be sent";
				TTCN_error(
						"SocketCAN sending CAN data with write() failed, as more than BCM_FRAME_BUFFER_SIZE number of CAN frames to be sent");
			} else {
				const Bcm::SocketCAN__bcm__frame& bcm__tx__msg =
						send_par.bcm__tx__msg();

				bcm_msg.msg_head.opcode = bcm__tx__msg.opcode();
				bcm_msg.msg_head.flags = bit2int(
						send_par.bcm__tx__msg().flags());
				bcm_msg.msg_head.count = bcm__tx__msg.count();
				bcm_msg.msg_head.ival1.tv_sec = bcm__tx__msg.ival1().tv__sec();
				bcm_msg.msg_head.ival1.tv_usec =
						bcm__tx__msg.ival1().tv__usec();
				bcm_msg.msg_head.ival2.tv_sec = bcm__tx__msg.ival2().tv__sec();
				bcm_msg.msg_head.ival2.tv_usec =
						bcm__tx__msg.ival2().tv__usec();
				bcm_msg.msg_head.can_id = bcm__tx__msg.can__id();
				bcm_msg.msg_head.nframes = nframes;

				log("SocketCAN: Sending BCM Message)");
				logInteger(" opcode: ", bcm__tx__msg.opcode());
				logBitstring(" flags: ", bcm__tx__msg.flags());
				logInteger(" count: ", bcm__tx__msg.count());
				logInteger(" ival1: ", bcm__tx__msg.ival1().tv__sec());
				logInteger(" ival1: ", bcm__tx__msg.ival1().tv__usec());
				logInteger(" ival2: ", bcm__tx__msg.ival2().tv__sec());
				logInteger(" ival2: ", bcm__tx__msg.ival2().tv__usec());
				logInteger(" can_id: ", bcm__tx__msg.can__id());
				logInteger(" nframes: ", nframes);

				for (int i = 0; i < nframes; i++) {
					const Bcm::SocketCAN__bcm__frame_frames_can__frame& frame =
							bcm__tx__msg.frames().can__frame();

					bcm_msg.frame[i].can_id = frame[i].can__id();
					unsigned int can_dlc;
					can_dlc = frame[i].can__pdu().lengthof();
					if (can_dlc > CAN_MAX_DLEN) {
						TTCN_error(
								"SocketCAN writing data: CAN pdu size too large\n");
						can_dlc = CAN_MAX_DLEN;
					};
					log(" containing CAN frame:)");
					logInteger("   can id: ", frame[i].can__id());
					logInteger("   can dlc: ", can_dlc);

					bcm_msg.frame[i].can_dlc = can_dlc;
					for (unsigned int j = 0; j < can_dlc; j++) {
						bcm_msg.frame[i].data[j] = oct2int(
								frame[i].can__pdu()[j]);
						logOctet("   data: ", frame[i].can__pdu()[j]);
					}
				}
				// assuming that the struct within the structure are aligned cm_msg without passing
				// BCM_write does not calculate unused fields from nframes to BCM_FRAME_BUFFER_SIZE
				nrOfBytestoSend = sizeof(struct bcm_msg_head)
						+ nframes * sizeof(struct can_frame);

				nrOfBytesSent = write(sock, &bcm_msg, (int) nrOfBytestoSend);

				if ((nrOfBytesSent) < 0) {
					int myerrno = errno;
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
					result.result().err() = myerrno;
					result.result().err__text() =
							"SocketCAN sending CAN data with write() failed";
					logInteger("bcm_msg.msg_head.can_id: ",
							(bcm_msg.msg_head.can_id));
					logInteger("bcm_msg.msg_head.count: ",
							bcm_msg.msg_head.count);
					logInteger("bcm_msg.msg_head.flags: ",
							bcm_msg.msg_head.flags);
					logInteger("bcm_msg.msg_head.ival1.tv_sec: ",
							bcm_msg.msg_head.ival1.tv_sec);
					logInteger("bcm_msg.msg_head.ival1.tv_usec: ",
							bcm_msg.msg_head.ival1.tv_usec);
					logInteger("bcm_msg.msg_head.ival2.tv_sec: ",
							bcm_msg.msg_head.ival2.tv_sec);
					logInteger("bcm_msg.msg_head.ival2.tv_usec: ",
							bcm_msg.msg_head.ival2.tv_usec);
					logInteger("bcm_msg.msg_head.nframes: ",
							bcm_msg.msg_head.nframes);
					logInteger("bcm_msg.msg_head.opcode: ",
							bcm_msg.msg_head.opcode);

					TTCN_error(
							//"SocketCAN sending CAN data with write() failed");
							"SocketCAN sending CAN data with write() failed. nrOfBytestoSend: %d, sizeof(struct bcm_msg_head): %d, nframes: %d, sizeof(struct can_frame): %d, nrOfBytesSent: %d, errno: %d\n",
							nrOfBytestoSend,
							((int) sizeof(struct bcm_msg_head)),
							((int) nframes), ((int) sizeof(struct can_frame)),
							(int) nrOfBytesSent, (int) myerrno);
				} else {
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
					result.result().err() = nrOfBytesSent;
					result.result().err__text() = OMIT_VALUE;
				}
				log("Nr of bytes sent = %d", nrOfBytesSent);

				if (nrOfBytesSent != nrOfBytestoSend) {
					TTCN_error(
							"SocketCAN frame  write failed: %d bytes were sent instead of %d",
							nrOfBytesSent, nrOfBytestoSend);
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
					result.result().err() = OMIT_VALUE;
					result.result().err__text() =
							"SocketCAN write failed as wrong number of bytes have been written";
				}
			}
		}
			break;
#ifdef BCM_CANFD_SUPPORT
		case Bcm::SocketCAN__bcm__frame_frames::ALT_canfd__frame: {
			int nrOfBytesSent = 0;
			int nrOfBytestoSend = 0;
			struct {
				struct bcm_msg_head msg_head;
				struct canfd_frame frame[BCM_FRAME_BUFFER_SIZE];
			} bcm_msg;

			const Bcm::SocketCAN__bcm__frame& bcm__tx__msg =
					send_par.bcm__tx__msg();

			unsigned int nframes =
					bcm__tx__msg.frames().canfd__frame().lengthof();

			if (nframes > BCM_FRAME_BUFFER_SIZE) {
				TTCN_error(
						"SocketCAN writing data: number of CAN FD frames too large: %d \n",
						nframes);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = errno;
				result.result().err__text() =
						"SocketCAN sending CAN FD data with write() failed, as more than BCM_FRAME_BUFFER_SIZE number of CAN FD frames to be sent";
				TTCN_error(
						"SocketCAN sending CAN FD data with write() failed, as more than BCM_FRAME_BUFFER_SIZE number of CAN FD frames to be sent");
			} else {
				const Bcm::SocketCAN__bcm__frame& bcm__tx__msg =
						send_par.bcm__tx__msg();

				bcm_msg.msg_head.opcode = bcm__tx__msg.opcode();
				bcm_msg.msg_head.flags = bit2int(
						send_par.bcm__tx__msg().flags());
				bcm_msg.msg_head.count = bcm__tx__msg.count();
				bcm_msg.msg_head.ival1.tv_sec = bcm__tx__msg.ival1().tv__sec();
				bcm_msg.msg_head.ival1.tv_usec =
						bcm__tx__msg.ival1().tv__usec();
				bcm_msg.msg_head.ival2.tv_sec = bcm__tx__msg.ival2().tv__sec();
				bcm_msg.msg_head.ival2.tv_usec =
						bcm__tx__msg.ival2().tv__usec();
				bcm_msg.msg_head.nframes = nframes;

				log("SocketCAN: Sending BCM Message)");
				logInteger(" opcode: ", bcm__tx__msg.opcode());
				logBitstring(" flags: ", bcm__tx__msg.flags());
				logInteger(" count: ", bcm__tx__msg.count());
				logInteger(" ival1: ", bcm__tx__msg.ival1().tv__sec());
				logInteger(" ival1: ", bcm__tx__msg.ival1().tv__usec());
				logInteger(" ival2: ", bcm__tx__msg.ival2().tv__sec());
				logInteger(" ival2: ", bcm__tx__msg.ival2().tv__usec());
				logInteger(" can_id: ", send_par.bcm__tx__msg().can__id());
				logInteger(" nframes: ", nframes);

				for (unsigned int i = 0; i < nframes; i++) {
					const Bcm::SocketCAN__bcm__frame_frames_canfd__frame& frame =
							bcm__tx__msg.frames().canfd__frame();

					bcm_msg.frame[i].can_id = frame[i].can__id();
					bcm_msg.frame[i].flags = bit2int(frame[i].can__flags());
					unsigned int len = frame[i].can__pdu().lengthof();
					if (len > CANFD_MAX_DLEN) {
						TTCN_error("Writing data: CAN FD pdu size too large\n");
						len = CANFD_MAX_DLEN;
					};
					log(" containing CAN FD frame:)");
					logInteger("   can id: ", frame[i].can__id());
					logInteger("   can len: ", len);

					bcm_msg.frame[i].len = len;
					for (unsigned int j = 0; j < len; j++) {
						bcm_msg.frame[i].data[j] = oct2int(
								frame[i].can__pdu()[j]);
						logOctet("   data: ", frame[i].can__pdu()[j]);
					}
				}
				// assuming that the structs within the structure are aligned cm_msg without passing
				// BCM_write does not calculate unused fields from nframes to BCM_FRAME_BUFFER_SIZE
				nrOfBytestoSend = sizeof(struct bcm_msg_head)
						+ nframes * sizeof(struct canfd_frame);
				nrOfBytesSent = write(sock, &bcm_msg, nrOfBytestoSend);

				if (nrOfBytesSent < 0) {
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
					result.result().err() = errno;
					result.result().err__text() =
							"SocketCAN sending CAN FD data with write() failed";
					TTCN_error(
							"SocketCAN sending CAN FD data with write() failed");
				} else {
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
					result.result().err() = OMIT_VALUE;
					result.result().err__text() = OMIT_VALUE;
				}
			}

			log("Nr of bytes sent = %d", nrOfBytesSent);

			if (nrOfBytesSent != nrOfBytestoSend) {
				TTCN_error(
						"SocketCAN CAN fd frame write failed: %d bytes were sent instead of %d",
						nrOfBytesSent, nrOfBytestoSend);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() =
						"SocketCAN write failed as wrong number of bytes have been written";
			}
		}
			break;
#endif //BCM_CANFD_SUPPORT

		default:
			TTCN_error("SocketCAN write unknown frame type error");
			result.result().result__code() =
					SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
			result.result().err() = OMIT_VALUE;
			result.result().err__text() =
					"SocketCAN write unknown frame type error";
			break;
		}
	} else {
		TTCN_error(
				"SocketCAN  write data failed due to unknown socket reference: %d \n",
				cn);
		result.result().result__code() =
				SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
		result.result().err() = OMIT_VALUE;
		result.result().err__text() =
				"SocketCAN  write data failed due to unknown socket reference";
	}
	incoming_message(result);
	log(
			"leaving SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__write__data)");
}

void SocketCAN__PT_PROVIDER::outgoing_send(
		const SocketCAN__Types::SocketCAN__setsockopt& send_par) {
	log(
			"entering SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__setsockopt)");

	int sock;
	int cn = send_par.id();
	int res;
	SocketCAN__Types::SocketCAN__setsockopt__result result;

	if ((cn < sock_list_length) and (sock_list[cn].status == SOCKET_OPEN)) {
		sock = sock_list[cn].fd;

		SocketCAN__Types::SocketCAN__setsockopt__commandu::union_selection_type command_selection =
				send_par.command().get_selection();

		switch (command_selection) {
		case SocketCAN__Types::SocketCAN__setsockopt__commandu::ALT_rfilter: {

			std::size_t rfilter_size = (sizeof(send_par.command().rfilter())
					/ sizeof(send_par.command().rfilter()[0]));

			struct can_filter rfilter[rfilter_size];

			if (rfilter_size == 0) {
				// deactivate filters
				res = setsockopt(sock, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);
			} else {
				for (std::size_t i = 0; i < rfilter_size; i++) {
					rfilter[i].can_id =
							send_par.command().rfilter()[i].can__id();
					rfilter[i].can_mask =
							send_par.command().rfilter()[i].can__mask();
				};
				res = setsockopt(sock, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter,
						sizeof(rfilter));
			}
			if (res < 0) {
				TTCN_error(
						"SocketCAN  setsockopt rfilter failed with error code %d:\n",
						errno);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = errno;
				result.result().err__text() =
						"SocketCAN  setsockopt rfilter failed";

			} else {
				log("SocketCAN: setsockopt rfilter successful on socket %d",
						sock);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() = OMIT_VALUE;
			}
		}
			break;

		case SocketCAN__Types::SocketCAN__setsockopt__commandu::ALT_err__mask: {
			can_err_mask_t err_mask = bit2int(send_par.command().err__mask());
			res = setsockopt(sock, SOL_CAN_RAW, CAN_RAW_ERR_FILTER, &err_mask,
					sizeof(err_mask));
			if (res < 0) {
				int myerrno = errno;
				TTCN_error(
						"SocketCAN  setsockopt can__err__mask failed with error code %d:\n",
						myerrno);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = myerrno;
				result.result().err__text() =
						"SocketCAN  setsockopt can__err__mask failed";
			} else {
				log(
						"SocketCAN: setsockopt can__err__mask successful on socket %d",
						sock);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() = OMIT_VALUE;
			}
		}
			break;

		case SocketCAN__Types::SocketCAN__setsockopt__commandu::ALT_loopback: {

			int loopback = send_par.command().loopback();
			res = setsockopt(sock, SOL_CAN_RAW, CAN_RAW_LOOPBACK, &loopback,
					sizeof(loopback));
			if (res < 0) {
				int myerrno = errno;
				TTCN_error(
						"SocketCAN  setsockopt loopbackfailed with error code %d:\n",
						myerrno);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = myerrno;
				result.result().err__text() =
						"SocketCAN  setsockopt loopback failed";
			} else {
				log("SocketCAN: setsockopt loopback successful on socket %d",
						sock);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() = OMIT_VALUE;
			}
		}
			break;

		case SocketCAN__Types::SocketCAN__setsockopt__commandu::ALT_recv__own__msgs: {

			int recv_own_msgs = send_par.command().recv__own__msgs();
			res = setsockopt(sock, SOL_CAN_RAW, CAN_RAW_RECV_OWN_MSGS,
					&recv_own_msgs, sizeof(recv_own_msgs));
			if (res < 0) {
				TTCN_error(
						"SocketCAN  setsockopt recv__own__msg failed with error code %d:\n",
						errno);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = errno;
				result.result().err__text() =
						"SocketCAN  setsockopt recv__own__msg failed";
			} else {
				log(
						"SocketCAN: setsockopt recv__own__msg successful on socket %d",
						sock);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() = OMIT_VALUE;
			}
		}
			break;

		case SocketCAN__Types::SocketCAN__setsockopt__commandu::ALT_fd__frames: {

			int fd_frames = send_par.command().fd__frames();

			res = setsockopt(sock, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &fd_frames,
					sizeof(fd_frames));
			if (res < 0) {
				TTCN_error(
						"SocketCAN  setsockopt fd__frames failed with error code %d:\n",
						errno);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
				result.result().err() = errno;
				result.result().err__text() =
						"SocketCAN  setsockopt fd__frames failed";
			} else {
				log("SocketCAN: setsockopt fd__frames successful on socket %d",
						sock);
				result.result().result__code() =
						SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
				result.result().err() = OMIT_VALUE;
				result.result().err__text() = OMIT_VALUE;
			}
		}
			break;
		case SocketCAN__Types::SocketCAN__setsockopt__commandu::ALT_join__filters: {
			{
				int join_filters = send_par.command().join__filters();

				res = setsockopt(sock, SOL_CAN_RAW, CAN_RAW_JOIN_FILTERS,
						&join_filters, sizeof(join_filters));
				if (res < 0) {
					TTCN_error(
							"SocketCAN  setsockopt join__filters failed with error code %d:\n",
							errno);
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
					result.result().err() = errno;
					result.result().err__text() =
							"SocketCAN  setsockopt join__filters failed";
				} else {
					log(
							"SocketCAN: setsockopt join__filterssuccessful on socket %d",
							sock);
					result.result().result__code() =
							SocketCAN__Types::SocketCAN__Result__code::SocketCAN__SUCCESS;
					result.result().err() = OMIT_VALUE;
					result.result().err__text() = OMIT_VALUE;
				}
			}
		}
			break;
		default: {
			TTCN_error(
					"SocketCAN: Unknown SocketCAN_setsockopt commandu union selection: %d \n",
					cn);
			result.result().result__code() =
					SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
			result.result().err() = OMIT_VALUE;
			result.result().err__text() =
					"SocketCAN: Unknown SocketCAN_setsockopt commandu union selection";
			break;
		}
		}
	} else {
		TTCN_error("SocketCAN: Unknown socket reference: %d \n", cn);
		result.result().result__code() =
				SocketCAN__Types::SocketCAN__Result__code::SocketCAN__ERROR;
		result.result().err() = errno;
		result.result().err__text() = "SocketCAN: Unknown socket reference";
	}
	incoming_message(result);
	log("leaving SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__setsockopt)");
}

void SocketCAN__PT_PROVIDER::outgoing_send(
		const SocketCAN__Types::SocketCAN__close& send_par) {
	log("entering SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__close)");
	int sock = sock_list[send_par.id()].fd;

	sock_list[send_par.id()].status = SOCKET_NOT_ALLOCATED;
	sock_list[send_par.id()].fd = 0;
	sock_list[send_par.id()].protocol_family =
			SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_NO_PROTOCOL;
	num_of_sock--;
	Handler_Remove_Fd_Read(sock);

	close(sock);

	log("leaving SocketCAN__PT_PROVIDER::outgoing_send(SocketCAN__close)");
}

void SocketCAN__PT_PROVIDER::reset_configuration() {
	free(can_interface_name);
	can_interface_name = NULL;
	debugging = false;
	debugging_configured = false;
}

void SocketCAN__PT_PROVIDER::InitStrPar(char *&par, const char* name,
		const char* val) {
	if (name)
		log("%s: Reading testport parameter: "
				"%s = %s", port_name, name, val);

	if (par)
		free(par);
	par = (char*) malloc(strlen(val) + 1);
	if (par == NULL)
		TTCN_error("Not enough memory.");
	strcpy(par, val);
}

void SocketCAN__PT_PROVIDER::log(const char *fmt, ...) {
	if (debugging == true) {
		TTCN_Logger::begin_event(TTCN_DEBUG);
		TTCN_Logger::log_event("SocketCAN test port (%s): ", get_name());
		va_list args;
		va_start(args, fmt);
		TTCN_Logger::log_event_va_list(fmt, args);
		va_end(args);
		TTCN_Logger::end_event();
	}
}

void SocketCAN__PT_PROVIDER::logOctet(const char *prompt,
		const OCTETSTRING& msg) {
	if (debugging == true) { //if debug
		TTCN_Logger::begin_event(TTCN_DEBUG);
		TTCN_Logger::log_event_str(prompt);
		TTCN_Logger::log_event("Size: %d,\nMsg: ", msg.lengthof());

		for (int i = 0; i < msg.lengthof(); i++) {
			TTCN_Logger::log_event(" %02x", ((const unsigned char*) msg)[i]);
		}
		TTCN_Logger::log_event("\n");
		TTCN_Logger::end_event();
	}
}

void SocketCAN__PT_PROVIDER::logHex(const char *prompt, const HEXSTRING& msg) {
	if (debugging == true) { //if debug
		TTCN_Logger::begin_event(TTCN_DEBUG);
		TTCN_Logger::log_event_str(prompt);
		TTCN_Logger::log_event("Size: %d,\nMsg: ", msg.lengthof());

		for (int i = 0; i < msg.lengthof(); i++) {
			TTCN_Logger::log_event(" %02x", ((const unsigned char*) msg)[i]);
		}
		TTCN_Logger::log_event("\n");
		TTCN_Logger::end_event();
	}
}

void SocketCAN__PT_PROVIDER::logInteger(const char *prompt, const int number) {
	if (debugging) { //if debug
		TTCN_Logger::begin_event(TTCN_DEBUG);
		TTCN_Logger::log_event_str(prompt);
		TTCN_Logger::log_event("Value: %d,\n: ", number);
		TTCN_Logger::log_event("\n");
		TTCN_Logger::end_event();
	}
}

void SocketCAN__PT_PROVIDER::logBitstring(const char *prompt,
		const BITSTRING& msg) {
	if (debugging == true) { //if debug
		TTCN_Logger::begin_event(TTCN_DEBUG);
		TTCN_Logger::log_event_str(prompt);
		int len = msg.lengthof();
		TTCN_Logger::log_event("Size: %d,\nMsg: 0b", len);
		for (int i = 0; i < msg.lengthof(); i++) {
			TTCN_Logger::log_event("%d", (int) bit2int(msg[i]));
		}
		TTCN_Logger::log_event("\n");
		TTCN_Logger::end_event();
	}
}

void SocketCAN__PT_PROVIDER::setUpSocket() {
	log("entering SocketCAN__PT_PROVIDER::setUpSocket()");
	log("leaving SocketCAN__PT_PROVIDER::setUpSocket()");
}

void SocketCAN__PT_PROVIDER::closeDownSocket() {
	log("entering SocketCAN__PT_PROVIDER::closeDownSocket()");

	for (int a = 0; a < sock_list_length; a++) {
		if (sock_list[a].status == SOCKET_OPEN) {
			sock_list[a].status = SOCKET_NOT_ALLOCATED;
			sock_list[a].protocol_family =
					SocketCAN__PortType::SocketCAN__PT_PROVIDER::SOCKET_NO_PROTOCOL;
			close(sock_list[a].fd);
			Handler_Remove_Fd_Read(sock_list[a].fd);
		}
	}

	Free(sock_list);
	sock_list = NULL;

	log("leaving SocketCAN__PT_PROVIDER::closeDownSocket()");
}

}
/* end of namespace */

