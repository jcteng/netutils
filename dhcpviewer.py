import socket

import struct

struct.pack("")
# 
# from rfc 1531
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | op(1) | htype(1) | hlen(1) | hops(1) |
# | xid(4) |
# | secs(2) | flags(2) |
# | ciaddr(4) |
# | yiaddr(4) |
# | siaddr(4) |
# | giaddr(4) |
# | chaddr(16) |
# | sname(64) |
# | file(128) |
# | options(312) |
# +---------------------------------------------------------------+
DHCP_MESSAGE_FRAME = "!BBBBIHHIIII16s64s128s"

#decimal 99.130.83.99( or hexadecimal number 63.82.53.63)
DHCP_MAGIC_COOKIE = 0x63825363
RFC1497_EXT = ""


import random

DHCP_OPTS={
    0x0:{"name":"PAD"},
    0x1:"Subnet Mask",
    0x2:"time offset",
    0x3:"router",
    0x4:"time server",
    0x5:"name server",
    0x6:"Domain name server",
    0x7:"logger server",
    0x8:"cookie server",
    9: "LPR Server",
    10: "Impress Server",
    11: "Resource Location Server",
    12: "Host Name",
    13: "Boot File Size",
    14: "Merit Dump File",
    15: "Domain Name",
    16: "Swap Server",
    17: "Root Path",
    18: "Extensions Path",
    255: "End",
    19: "IP Forwarding Enable/Disable",
    20: "Non-Local Source Routing Enable/Disable",
    21: "Policy Filter",
    22: "Maximum Datagram Reassembly Size",
    23: "Default IP Time-to-live",
    24: "Path MTU Aging Timeout",
    25: "Path MTU Plateau Table",
    26: "Interface MTU",
    27: "All Subnets are Local",
    28: "Broadcast Address",
    29: "Perform Mask Discovery",
    30: "Mask Supplier",
    31: "Perform Router Discovery",
    32: "Router Solicitation Address",
    33: "Static Route",
    34: "Trailer Encapsulation Option",
    35: "ARP Cache Timeout",
    36: "Ethernet Encapsulation",
    37: "TCP Default TTL",
    38: "TCP Keepalive Interval",
    39: "TCP Keepalive Garbage",
    40: "Network Information Service Domain",
    41: "Network Information Servers",
    42: "Network Time Protocol Servers",
    43: "Vendor Specific Information",
    44: "NetBIOS over TCP/IP Name Server",
    45: "NetBIOS over TCP/IP Datagram Distribution Server",
    46: "NetBIOS over TCP/IP Node Type",
    47: "NetBIOS over TCP/IP Scope",
    48: "X Window System Font Server",
    49: "X Window System Display Manager",
    64: "Network Information Service+ Domain",
    65: "Network Information Service+ Servers",
    68: "Mobile IP Home Agent",
    69: "Simple Mail Transport Protocol (SMTP) Server",
    70: "Post Office Protocol (POP3) Server",
    71: "Network News Transport Protocol (NNTP) Server",
    72: "Default World Wide Web (WWW) Server",
    73: "Default Finger Server",
    74: "Default Internet Relay Chat (IRC) Server",
    75: "StreetTalk Server",
    76: "StreetTalk Directory Assistance (STDA) Server",
    50: "Requested IP address",
    51: "IP address Lease Time",
    52: "Option Overload",
    53: "DHCP Message Type",
    54: "Server Identifier",
    55: "Parameter Request List",
    56: "Message",
    57: "Maximum DHCP Message Size",
    58: "Renewal (T1) Time Value",
    59: "Rebinding (T2) Time Value",
    60: "Vendor class identifier",
    61: "Client-identifier",
    66: "TFTP server name",
    67: "Bootfile name",
    95:"PXE tftp server",

}


class Message_Frame(object):
    op = 1
    htype = 1
    hlen = 6
    hops = 0
    xid = 0
    secs = 0x0000
    flags = 0x8000
    ciaddr = 0x0
    yiaddr = 0x0
    siaddr = 0x0
    giaddr = 0x0
    chaddr = "\x00" * 16
    sname = "\x00" * 64
    ffile = "\x00" * 128
    options = ""
    __options = {}
    def to_dict(self):
        out_dict = {}
        for name in dir(self):
            if not name.startswith('__') and not callable(self.__getattribute__(name)):
                out_dict[name] = self.__getattribute__(name)
        return out_dict




    def decode_dhcp_options(self,opt):
        print struct.unpack("BB",opt)

    def disp_frame_body(self):

        def int_to_ip_str(in32):
            return "%d.%d.%d.%d"%(in32>>24,(in32>>16)&0xff,(in32>>8)&0xff,(in32)&0xff)

        yiaddr = int_to_ip_str(self.yiaddr)
        ciaddr = int_to_ip_str(self.ciaddr)
        siaddr = int_to_ip_str(self.siaddr)
        chaddr = "%x-%x-%x-%x-%x-%x"%struct.unpack("!BBBBBB",self.chaddr[:6])
        file = self.ffile.replace("\00","")
        sname = self.sname.replace("\00","")


        out_str = '''op=%d
sname=%s
file=%s
xid=%x
yiaddr=%s
ciaddr=%s
siaddr=%s
chaddr=%s'''%(self.op,sname,file,self.xid,
                      yiaddr,ciaddr,siaddr,chaddr
                                 )
        return out_str

    def decode_options(self):
        magic = struct.unpack("!I",self.options[:4])[0]
        if DHCP_MAGIC_COOKIE==int(magic):
            remain = self.options[4:]
            while True:
                code = struct.unpack("B",remain[:1])[0]
                if code == 0xff:
                    break
                size = struct.unpack("B", remain[1:2])[0]
                value_size = size
                value = ""
                if value_size!=0:
                    value = remain[2:2+value_size]
                if value_size==4:
                    ip1,ip2,ip3,ip4 = struct.unpack("!BBBB",value)
                    print "<%s(%d) len(%d)>:[%s]-[%d.%d.%d.%d] (%s)" % (
                    DHCP_OPTS.get(code, "UNKOWN Options"), code, size, value,ip1,ip2,ip3,ip4, str(value).encode('hex'))

                else:
                    print "<code-%s(%d) len(%d)>value:[%s] (%s)"%(DHCP_OPTS.get(code,"UNKOWN Options"),code,size,value,str(value).encode('hex'))

                remain = remain[value_size+2:]
        else:
            print "UNKOWN magic code",self.options[0:3]

    @staticmethod
    def decode_frame(frame,instance=None):

        if len(frame)<struct.calcsize(DHCP_MESSAGE_FRAME):
            raise Exception("Input frame too short")
        base_len = struct.calcsize(DHCP_MESSAGE_FRAME)
        base_frame = frame[0:base_len]

        if instance==None:
            instance = Message_Frame()
        instance.options = frame[base_len:]

        (instance.op, instance.htype, instance.hlen, instance.hops,
        instance.xid, instance.secs,
        instance.flags,
        instance.ciaddr,
        instance.yiaddr,
        instance.siaddr,
        instance.giaddr,
        instance.chaddr,
        instance.sname, instance.ffile ) =struct.unpack(DHCP_MESSAGE_FRAME,base_frame)
        instance.decode_options()
        return instance


    def add_dhcp_options(self,code,value):
        self.__options[code]=value



    def  frame_pack(self=None,**kwargs):
        for key,value in kwargs.items():
            setattr(self,key,value)

        xid = kwargs.get("xid",self.xid)
        if xid==0:
            xid = random.randint(0,0xffffffff)

        buf = struct.pack(DHCP_MESSAGE_FRAME,self.op,self.htype,self.hlen,self.hops,
                          self.xid,self.secs,
                          self.flags,
                          self.ciaddr,
                          self.yiaddr,
                          self.siaddr,
                          self.giaddr,
                          self.chaddr,
                          self.sname,self.ffile)
        #add magic cookie first
        self.options = struct.pack("!I",DHCP_MAGIC_COOKIE)
        for code,value in self.__options.items():
            size = len(value)
            fmt_tmp = "!BB%ds"%size
            self.options = self.options + struct.pack(fmt_tmp,code,size,value)
        buf = buf + self.options +'\xff'



        return buf,xid

def dhcp_discovery(server_ip="255.255.255.255"):
    source_ip = "0.0.0.0"
    dist_ip = server_ip
    dist_port = 67
    source_port = 68
    udpSerSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpSerSock.bind((source_ip,source_port))
    udpSerSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udpSerSock.settimeout(2)
    mf = Message_Frame()
    #discover
    mf.add_dhcp_options(code=53,value='\x01')

    #need a mac
    out_frame , xid =mf.frame_pack(chaddr="\x4c\xbb\x58\x96\e4\7b\00\00\00\00\00\00\00\00\00\00")

    print "send discovery frame",xid
    udpSerSock.sendto(out_frame,(dist_ip,dist_port))

    while True:
        try:
            recved ,addr = udpSerSock.recvfrom(1024)
            print "---got-from-dhcp--server--%s:%d----------"%addr
            recv_mf = Message_Frame.decode_frame(recved)
            print recv_mf.disp_frame_body()
        except socket.timeout:
            return


import sys
if __name__=="__main__":

    if(len(sys.argv)==2):
        dhcp_discovery(sys.argv[1])
    else:
        dhcp_discovery()

#sniffer_udp()