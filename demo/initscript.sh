 ##############################################################################
 # Copyright (c) 2000-2018 Ericsson Telecom AB
 # All rights reserved. This program and the accompanying materials
 # are made available under the terms of the Eclipse Public License v2.0
 # which accompanies this distribution, and is available at
 # https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
 #
 # Contributors:
 # Michael Josenhans
 ##############################################################################



#!/bin/bash

# Add vcan module to kernel
sudo modprobe vcan

# Setup of virtual can vcan0
sudo ip link add dev vcan0 type vcan
# set it up at as a canfd can interface
sudo ip link set vcan0 mtu 72
sudo ip link set vcan0 up

# Setup of virtual can vcan1
sudo ip link add dev vcan1 type vcan
sudo ip link set vcan1 up

# example configuration of a physical can bus interface
#sudo ip link set can0 up type can bitrate 1000000

ifconfig
