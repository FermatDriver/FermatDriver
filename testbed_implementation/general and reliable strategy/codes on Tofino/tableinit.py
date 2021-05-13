from ipaddress import ip_address

p4 = bfrt.fermat_ecmp.pipe

path="/mnt/onl/data/table10/"
'''tableportmap_t1'''

portmap_t1_conf=open(path+"portmap_t1_conf.txt")

table=p4.Ingress.portmap_t1
for t in portmap_t1_conf:
    d=t.split()
    table.add_with_portmap1(ingress_port=int(d[0]), res=int(d[1]),oft=int(d[2]))

'''tableportmap_timeflip_t'''
portmap_t2_conf=open(path+"portmap_t1_conf.txt")

table=p4.Ingress.portmap_timeflip_t
for t in portmap_t2_conf:
    d=t.split()
    table.add_with_tf(ucast_egress_port=int(d[0]),timeflip=int(d[1]),oft=int(d[2]))
'''work_tt'''
work_tt_conf=open(path+"work_tt_conf.txt")

table=p4.Ingress.work_tt
for t in work_tt_conf:
    d=t.split()
    table.add_with_work_t(ingress_port=int(d[0]), index=int(d[1]))

'''ipv4_host'''
ipv4_host_conf=open(path+"ipv4_host_conf.txt")
f= open(path+"current_host_conf.txt","w+")
table=p4.Ingress.ipv4_host
for t in ipv4_host_conf:
    f.write(t)
    d=t.split()
    table.add_with_send(src_addr=int(d[0],16), src_addr_mask=int(d[1],16), dst_addr=int(d[2],16), dst_addr_mask=int(d[3],16), protocol=int(d[4]), sp=int(d[5],16), sp_mask=int(d[6],16), dp=int(d[7],16), dp_mask=int(d[8],16), match_priority=int(d[9]),port=int(d[10]))
'''query_t'''

table=p4.Ingress.query_t
for t in range(0,16384):
    sip1=t&0x3000
    sip1=sip1>>12
    dip1=t&0x0c00
    dip1=dip1>>10
    ll1=t&0x0300
    ll1=ll1>>8
    proto=t&0xff;
    table.add_with_match(sip=sip1,dip=dip1,ll=ll1,protocol=proto,id=t*4)

'''ipv4_acl'''
ipv4_acl_conf=open(path+"ipv4_acl_conf.txt")
table=p4.Ingress.ipv4_acl
for t in ipv4_acl_conf:
    d=t.split();
    table.add_with_drop2(src_addr=int(d[0],16), src_addr_mask=int(d[1],16), dst_addr=int(d[2],16), dst_addr_mask=int(d[3],16), protocol=int(d[4]), sp=int(d[5],16), sp_mask=int(d[6],16), dp=int(d[7],16), dp_mask=int(d[8],16), match_priority=int(d[9]))

'''ecmp_select'''
ecmp_select_conf=open(path+"ecmp_select_conf.txt")

table=p4.Ingress.ecmp_select_t
for t in ecmp_select_conf:
    d=t.split()
    table.add_with_ecmp_select(dst_addr=ip_address(d[0]), ecmp=int(d[1]),port=int(d[2]))

'''arp_host'''
arp_host_conf=open(path+"arp_host_conf.txt")

table=p4.Ingress.arp_host
for t in arp_host_conf:
    d=t.split()
    table.add_with_unicast_send(proto_dst_addr=ip_address(d[0]), port=int(d[1]))

'''fermat_host'''
fermat_host_conf=open(path+"fermat_host_conf.txt")

table = p4.Ingress.fermat_host
for t in fermat_host_conf:
    d=t.split()
    table.add_with_unicast_send(ip_dst_addr=ip_address(d[0]), port=int(d[1]))

'''recover_host'''
recover_host_conf=open(path+"recover_host_conf.txt")

table = p4.Ingress.recover_host
for t in recover_host_conf:
    d=t.split()
    table.add_with_unicast_send(dst_addr=ip_address(d[0]), port=int(d[1]))
    
