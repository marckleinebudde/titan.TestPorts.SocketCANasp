#!/bin/bash

. ../gen_links.sh.inc

DIR=../src
FILES=( \
	Bcm.ttcn \
	Can.ttcn \
	CanError.ttcn \
	General_Types.ttcn \
	Raw.ttcn \
	SocketCAN_PortType.ttcn \
	SocketCAN_Templates.ttcn \
	SocketCAN_Types.ttcn \
)

FILES+=( SocketCAN_PT.cc )
FILES+=( SocketCAN_PT.hh )

gen_links ${DIR} ${FILES[@]}
