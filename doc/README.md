# titan.TestPorts.SocketCANasp

Main project page:

https://projects.eclipse.org/projects/tools.titan

The source code of the TTCN-3 compiler and executor:

https://github.com/eclipse/titan.core


References:
https://www.kernel.org/doc/Documentation/networking/can.txt

Other useful documentation:
https://docs.python.org/3/library/socket.html (search for: "AF_CAN")
https://media.readthedocs.org/pdf/python-can/latest/python-can.pdf
http%3A%2F%2Fwww.can-cia.de%2Ffileadmin%2Fresources%2Fdocuments%2Fproceedings%2F2012_hartkopp.pdf
http://www.can-cia.de/fileadmin/resources/documents/proceedings/2012_hartkopp.pdf
http://v2.can-newsletter.org/uploads/media/raw/46c15d02e1fdd3b04e671693ec548ff7.pdf

# See file: src/initscript.sh:

#--------------------------------------
#!/bin/bash
# based on ideas from: 
# 

# create a virtual can interface:

sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set vcan0 up

# or create a physical can interface

#sudo ip link set can0 up type can bitrate 1000000

ifconfig

#--------------------------------------

cd src
./demo/initscript.sh 

or alternatively
source demo/initscript.sh

make clean; make

ttcn3_start SocketCAN client.cfg

or to run a certain testcase:

ttcn3_start SocketCAN client.cfg  SocketCANtest.tc_can_raw1 SocketCANtest.tc_can_bcm1

Review the newly created log files in the src directory
and use e.g. Wireshark to trace the CAN interfacce.

#--------------------------------------
Notes:
-Using multiple Test interfacces:
 Currently the init script sets up multiple virtual can interfaces ("vcan0", 
 "vcan1" in oder to allow using multiple CAN interfaces.
 The CAN interfaces have to be defined in the TTCN configuration files or may 
 alternatively be defined in the optional parameters of port messages commands 
 ioctl and send_data.
 
 Handling of multiple CAN interfaces is work in progress and no test cases are
 provided. In order to configure usage with multiple test interfaces, 
 test interfaces for each interface have to be defined in the MTC.
 
-CAN RAW:
 CAN FD has been implemented, however not been tested.
 Depending on the availability of the C-code #define "CAN_FD_FRAME"
 in /usr/include/linux/can/bcm.h, CAN-FD support is enabled at compile time.
 The RAW setsockopt has path coverage. However no test coverage that insures
 the setsockopt functionality provided by the kernel is working correctly. 
 For this purpose in the future might be added additional test cases.

-CAN BCM:
 TX_SETUP, TX_DELETE have been tested, TX_READ is known to fail test cases.
 Some tests have indicated, that that SocketCAN BCM does not support concurrently
 active BCM channels.
 The BCM has test coverage for TX_SETUP and TX_DELETE. However no test coverage
 that insures the BCM functionality provided by the kernel is working correctly. 
 For this purpose in the future might be added additional test cases.
 Return values other than the error code by the BCM are not yet supported.
 BCM wth CAN FD frames has not been tested yet.

-Merging of logfiles:
 To merge the logfies from multiple Parallel Test Componets (PTCs) from a
 single run in timely order into sigle file, run:
   $ TTCN3_DIR/bin/ttcn3_logmerge -o log_merged.txt *.log
 The merged log-file is found at log_merged.txt
 
-Dunping CAN Frames using SocketCAN:
 To dump all received can frames of e.g. "vcan0" run a seperate terminal:
   $ candump "vcan0"
