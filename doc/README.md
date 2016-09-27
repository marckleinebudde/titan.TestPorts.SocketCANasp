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
./src/initscript.sh 

or alternatively
source src/initscript.sh

make clean; make
ttcn3_start SocketCANtest client.cfg  SocketCANtest.tc_can_raw1 SocketCANtest.tc_can_bcm1

Review the newly created log files in the src directory
and use e.g. Wireshark to trace the CAN interfacce.


