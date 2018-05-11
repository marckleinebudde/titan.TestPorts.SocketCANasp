#!/bin/bash

 ##############################################################################
 # Copyright (c) 2010, 2016  Ericsson AB
 # All rights reserved. This program and the accompanying materials
 # are made available under the terms of the Eclipse Public License v1.0
 # which accompanies this distribution, and is available at
 # http://www.eclipse.org/legal/epl-v10.html
 #
 # Contributors:
 # Michael Josenhans
 ##############################################################################

# Add vcan module to kernel
sudo modprobe vcan

# Setup of virtual can vcan0
sudo ip link add dev vcan0 type vcan

# set it up at as a canfd capable can interface
sudo ip link set vcan0 mtu 72
sudo ip link set vcan0 up

# or create a physical can interface
# sudo ip link set can0 up type can bitrate 1000000

ifconfig
