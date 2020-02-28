EtherPuppet
===========

What is EtherPuppet ?
---------------------

Etherpuppet is a small program for Linux that will create a virtual interface (TUN/TAP) on one machine from the ethernet interface of another machine through a TCP connection. Everything seen by the real interface will be seen by the virtual one. Everything sent to the virtual interface will be emitted by the real one. It has been designed because one often has a small machine as his Internet gateway, and sometimes want to run some big applications that need raw access to this interface, for sniffing (Ethereal, etc.) or for crafting packets that do not survive being reassembled, NATed, etc. It can even run on Linux embedded routers such as the Linksys WRT54G.

Detailed informations
---------------------

Etherpuppet is a small program for Linux that will create a voodoo doll for an Ethernet interface. You have to run the Etherpuppet on your machine to create the doll, which will have the shape of a virtual TUN/TAP interface (named by default puppet%d, where %d is a number). You also have to run Etherpuppet on the victim interface's machine. Both instances of Etherpuppet will communicate through TCP. Once this is done, everything seen by the real interface will be seen by the virtual one. Everything that will be sent to the virtual interface will be emitted by the real one. Parameters like IP address or MTU are transmitted once at the beginning from the real interface to the virtual one. Following changes won't be transmitted in either way.

Etherpuppet has been designed because one often has a small machine as his Internet gateway, and sometimes want to run some big applications that need a raw access to this interface, for sniffing (Ethereal, etc.) or for crafting packets that does not survive being reassembled, NATed, etc.
A static MIPS binary is even provided that can run on a Linksys WRT54G (at least on mine with the OpenWRT firmware), so that you can run scapy directly from your Linksys' interface.

* Warning: replicating your Internet firewall interface onto your LAN workstation is like plugging your workstation directly to Internet. Don't forget this point!
* Warning: nothing is done to ensure authentication or confidentiality. If you want that, use SSH tunneling (see also ``-S``)

.. sourcecode :: none

   Usage: etherpuppet {-s port|-c targetip:port} [-B|-S|-M <arg>] [-C] -i iface
          etherpuppet -m {-s port|-c targetip:port} [-I ifname]
   -s <port>        : listen on TCP port <port>
   -c <IP>:<port>   : connect to <IP>:<port>
   -i <iface>       : vampirize interface <iface>
   -I <ifname>      : choose the name of the virtual interface
   -m               : master mode
   -B               : do not use any BPF. Etherpuppet may see its own traffic!
   -S               : build BPF filter with SSH_CONNECTION environment variable
   -M src:sp,dst:dp : build BPF filter from argument
   -C               : don't copy real interface parameters to virtual interface
   TCP communication can be established in any direction (from master to slave or from slave to master).


Traffic seen by the real interface is sent through the TCP connection to the doll interface. Thus, it is important that this connection is not seen by the real interface (or else, we'll have a cute infinite traffic loop). When the connection is established, the following BPF is pushed on the PF_PACKET socket :


.. sourcecode:: none

   not (tcp and
         ( (dst 68.69.70.71 and dst port 0xABCD and src port 0x1234 and src 64.65.66.67) or
           (src 68.69.70.71 and src port 0xABCD and dst port 0x1234 and dst 64.65.66.67)
         )
       )

The source and destination are by default the TCP connection end points. If you go through SSH tunneling, you can use the ``-S`` option to use ``SSH_CONNECTION`` environment variable content instead, so that you will filter out the SSH connection of your current session and not the connection to the local SSH tunnel end point (which is pointless). If this still not fit your needs, you can manually specify the connection end points with ``-M``.

If you connect two Etherpuppet instances in master mode, you'll get a TCP tunnel through virtual interfaces.

If you connect two Etherpuppet instances in slave mode, you may get some kind of inefficient distributed bridge, but more probably, you'll get a big mess.

