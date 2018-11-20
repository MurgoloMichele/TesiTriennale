from multiprocessing import Pool, Queue, Lock
import datetime
import os
import sys
import math
import fnmatch
import gzip
import shutil

""" String for every binetflow field """
string = []
ipv4_src_addr = []
ipv4_dst_addr = []
first_switched = []
last_switched = []
protocol = []
src_port = []
dst_port = []
biflow = []
src_tos = [] 
in_pkts = []
out_pkts = []
in_bytes = []
out_bytes = []

'''
Assigned Internet Protocol Numbers
nProbe files represents AIPN with numbers.
binetflow represents AIPN with keyword.
Dictionary data structure, access costs is O(1)
'''
dict_protocols = {
    "0":"hopopt",
    "1":"icmp",
    "2":"igmp",
    "3":"ggp",
    "4":"ipv4",
    "5":"st",
    "6":"tcp",
    "7":"cbt",
    "8":"egp",
    "9":"igp",
    "10":"bbn-rcc-mon",
    "11":"nvp-ii",
    "12":"pup",
    "13":"argus",
    "14":"emcon",
    "15":"xnet",
    "16":"chaos",
    "17":"udp",
    "18":"mux",
    "19":"dcn-meas",
    "20":"hmp",
    "21":"prm",
    "22":"xns-idp",
    "23":"trunk-1",
    "24":"trunk-2",
    "25":"leaf-1",
    "26":"leaf-2",
    "27":"rdp",
    "28":"irtp",
    "29":"iso-tp4",
    "30":"netblt",
    "31":"mfe-nsp",
    "32":"merit-inp",
    "33":"dccp",
    "34":"3pc",
    "35":"idpr",
    "36":"xtp",
    "37":"ddp",
    "38":"idpr-cmtp",
    "39":"tp++",
    "40":"il",
    "41":"ipv6",
    "42":"sdrp",
    "43":"ipv6-route",
    "44":"ipv6-frag",
    "45":"idrp",
    "46":"rsvp",
    "47":"gre",
    "48":"dsr",
    "49":"bna",
    "50":"esp",
    "51":"ah",
    "52":"i-nlsp",
    "53":"swipe",
    "54":"narp",
    "55":"mobile",
    "56":"tlsp",
    "57":"skip",
    "58":"ipv6-icmp",
    "59":"ipv6-nonxt",
    "60":"ipv6:opts",
    "61":"any-host-internal-protocol",
    "62":"cftp",
    "63":"any-local-network",
    "64":"sat-expak",
    "65":"kryptolan",
    "66":"rvd",
    "67":"ippc",
    "68":"any-distributed-file-system",
    "69":"sat-mon",
    "70":"visa",
    "71":"ipcv",
    "72":"cpnx",
    "73":"cphb",
    "74":"wsn",
    "75":"pvp",
    "76":"br-sat-mon",
    "77":"sun-nd",
    "78":"wb-mon",
    "79":"wb-expak",
    "80":"iso-ip",
    "81":"vmtp",
    "82":"secure-vmtp",
    "83":"vines",
    "84":"ttp",
    "85":"nsfnet-igp",
    "86":"dgp",
    "87":"tcf",
    "88":"eigrp",
    "89":"ospfigp",
    "90":"sprite-rpc",
    "91":"larp",
    "92":"mtp",
    "93":"ax.25",
    "94":"ipip",
    "95":"micp",
    "96":"scc-sp",
    "97":"etherip",
    "98":"encap",
    "99":"any-private-encryption-scheme",
    "100":"gmtp",
    "101":"ifmp",
    "102":"pnni",
    "103":"pim",
    "104":"aris",
    "105":"scps",
    "106":"qnx",
    "107":"a/n",
    "108":"ipcomp",
    "109":"snp",
    "110":"compaq-peer",
    "111":"ipx-in-ip",
    "112":"vrrp",
    "113":"pgm",
    "114":"any-0-hop-protocol",
    "115":"l2tp",
    "116":"ddx",
    "117":"iatp",
    "118":"stp",
    "119":"srp",
    "120":"uti",
    "121":"smp",
    "122":"sm",
    "123":"ptp",
    "124":"isis-over-ipv4",
    "125":"fire",
    "126":"crtp",
    "127":"crudp",
    "128":"sscopmce",
    "129":"iplt",
    "130":"sps",
    "131":"pipe",
    "132":"sctp",
    "133":"fc",
    "134":"rsvp-e2e-ignore",
    "135":"mobility-header",
    "136":"udplite",
    "137":"mpls-in-ip",
    "138":"manet",
    "139":"hip",
    "140":"shim6",
    "141":"wesp",
    "142":"rohc",
    "143":"unassigned",
    "144":"unassigned",
    "145":"unassigned",
    "146":"unassigned",
    "147":"unassigned",
    "148":"unassigned",
    "149":"unassigned",
    "150":"unassigned",
    "151":"unassigned",
    "152":"unassigned",
    "153":"unassigned",
    "154":"unassigned",
    "155":"unassigned",
    "156":"unassigned",
    "157":"unassigned",
    "158":"unassigned",
    "159":"unassigned",
    "160":"unassigned",
    "161":"unassigned",
    "162":"unassigned",
    "163":"unassigned",
    "164":"unassigned",
    "165":"unassigned",
    "166":"unassigned",
    "167":"unassigned",
    "168":"unassigned",
    "169":"unassigned",
    "170":"unassigned",
    "171":"unassigned",
    "172":"unassigned",
    "173":"unassigned",
    "174":"unassigned",
    "175":"unassigned",
    "176":"unassigned",
    "177":"unassigned",
    "178":"unassigned",
    "179":"unassigned",
    "180":"unassigned",
    "181":"unassigned",
    "182":"unassigned",
    "183":"unassigned",
    "184":"unassigned",
    "185":"unassigned",
    "186":"unassigned",
    "187":"unassigned",
    "188":"unassigned",
    "189":"unassigned",
    "190":"unassigned",
    "191":"unassigned",
    "192":"unassigned",
    "193":"unassigned",
    "194":"unassigned",
    "195":"unassigned",
    "196":"unassigned",
    "197":"unassigned",
    "198":"unassigned",
    "199":"unassigned",
    "200":"unassigned",
    "201":"unassigned",
    "202":"unassigned",
    "203":"unassigned",
    "204":"unassigned",
    "205":"unassigned",
    "206":"unassigned",
    "207":"unassigned",
    "208":"unassigned",
    "209":"unassigned",
    "210":"unassigned",
    "211":"unassigned",
    "212":"unassigned",
    "213":"unassigned",
    "214":"unassigned",
    "215":"unassigned",
    "216":"unassigned",
    "217":"unassigned",
    "218":"unassigned",
    "219":"unassigned",
    "220":"unassigned",
    "221":"unassigned",
    "222":"unassigned",
    "223":"unassigned",
    "224":"unassigned",
    "225":"unassigned",
    "226":"unassigned",
    "227":"unassigned",
    "228":"unassigned",
    "229":"unassigned",
    "230":"unassigned",
    "231":"unassigned",
    "232":"unassigned",
    "233":"unassigned",
    "234":"unassigned",
    "235":"unassigned",
    "236":"unassigned",
    "237":"unassigned",
    "238":"unassigned",
    "239":"unassigned",
    "240":"unassigned",
    "241":"unassigned",
    "242":"unassigned",
    "243":"unassigned",
    "244":"unassigned",
    "245":"unassigned",
    "246":"unassigned",
    "247":"unassigned",
    "248":"unassigned",
    "249":"unassigned",
    "250":"unassigned",
    "251":"unassigned",
    "252":"unassigned",
    "253":"experimentation-testing",
    "254":"experimentation-testing",
    "255":"reserved"
}

flow_direction = {
    "1":"<-",
    "2":"->"
}

'''
Binetflow file header
'''
CONST_HEADER_BINETFLOW = "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,srcUdata,dstUdata,Label"


'''
Function that returns the number of line in a file

@input:
fname, file name
'''
def file_len(fname):
    return sum(1 for line in gzip.open(fname))




if __name__ == "__main__":
    walk_dir = sys.argv[1]

    with open("file.binetflow", "w") as outfile:
        outfile.write(CONST_HEADER_BINETFLOW)
        
    for root,subdirs,files in os.walk(walk_dir, topdown=True):
        list_file_path = os.path.join(root, "my_directory_list.txt")

        with open(list_file_path, "wb") as list_file:
            for filename in files:
                if filename == "my_directory_list.txt":
                    continue
                file_path = os.path.join(root,filename)
           

                string.clear()
                ipv4_src_addr.clear()
                ipv4_dst_addr.clear()
                first_switched.clear()
                last_switched.clear()
                protocol.clear()
                src_port.clear()
                dst_port.clear()
                biflow.clear()
                src_tos.clear()
                in_pkts.clear()
                out_pkts.clear()
                in_bytes.clear()
                out_bytes.clear()

                with gzip.open(file_path, "rt") as infile:
                    for line in infile:
                        string = line.strip().split("|")
                        ipv4_src_addr.append(string[0])
                        ipv4_dst_addr.append(string[1])
                        first_switched.append(string[7])
                        last_switched.append(string[8])
                        protocol.append(string[12])
                        src_port.append(string[9])
                        dst_port.append(string[10])
                        biflow.append(string[19])
                        src_tos.append(string[13])
                        in_pkts.append(string[5])
                        out_pkts.append(string[22])
                        in_bytes.append(string[6])
                        out_bytes.append(string[23])

                    ipv4_src_addr.remove("IPV4_SRC_ADDR")
                    protocol.remove("PROTOCOL")
                    ipv4_dst_addr.remove("IPV4_DST_ADDR")
                    first_switched.remove("FIRST_SWITCHED")
                    last_switched.remove("LAST_SWITCHED")
                    src_port.remove("L4_SRC_PORT")
                    dst_port.remove("L4_DST_PORT")
                    biflow.remove("BIFLOW_DIRECTION")
                    src_tos.remove("SRC_TOS")
                    in_pkts.remove("IN_PKTS")
                    out_pkts.remove("OUT_PKTS")
                    in_bytes.remove("IN_BYTES")
                    out_bytes.remove("OUT_BYTES")

                i = 1
                length_file = file_len(file_path)
               

                with open("file.binetflow", "a") as outfile:
                    while i + 1 < length_file:
                        year,month,day,hour,minute = file_path.split("/")
                        minute,name,extension = minute.split(".")
                        last = float(last_switched[i])
                        first = float(first_switched[i])
                        tot_pkts = int(in_pkts[i]) + int(out_pkts[i])
                        tot_bytes = int(in_bytes[i]) + int(out_bytes[i])
                        
                        outfile.write("\n" + year + "/" + month + "/" + day + " " + hour + 
                        ":" + minute + ":" + first_switched[i][:2] + "." + 
                        first_switched[i][:6] + "," + '{:.6f}'.format(last - first) + "," + 
                        dict_protocols.get(protocol[i]) + "," + ipv4_src_addr[i] + 
                        "," + src_port[i] + "," + flow_direction.get(biflow[i]) + 
                        "," + ipv4_dst_addr[i] + "," + dst_port[i] + "," + "CON" "," + 
                        src_tos[i] + "," + "," + str(tot_pkts) + "," + str(tot_bytes) + 
                        "," + in_bytes[i] + ",,,")
                        i = i + 1
