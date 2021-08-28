#!/usr/bin/python

# Copyright (c) 2021, WAND Network Research Group
#                     Department of Computer Science
#                     University of Waikato
#                     Hamilton
#                     New Zealand
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330,
# Boston,  MA 02111-1307  USA
#
# @Author : Dimeji Fayomi

from pyroute2 import IPRoute
from pyroute2 import NFTables
from pr2modules import netlink
import ipaddress
from socket import AF_INET 
from socket import AF_INET6
import dataplane_pb2 
import dataplaneapi_pb2_grpc
import subprocess
import logging
import status
import iptc


class DataplaneStateHandler(dataplaneapi_pb2_grpc.DataplaneStateServicer):
    """gRPC request handler"""

    def __init__(self, _iproute):
        self.iproute = _iproute
        self.log = logging.getLogger("DataplaneStateHandler")

    def GetIfaces(self, request, context):
        with status.context(context):
            self.log.debug("Received interface request")
            response = dataplane_pb2.ReplyIfaces()
            ifaces = self.nlGetIfaces()
            nl_ifaces = []
            for iface in ifaces:
                ifindex, ifname, ifstate = iface
                proto_iface = dataplane_pb2.Interface()
                proto_iface.IfName = ifname
                proto_iface.IfIndex = ifindex
                neighbours = self.nlGetNeighFromIface(ifindex)
                addrs = self.nlGetIfaceAddr(ifindex)
                proto_iface.Neighbours.extend(neighbours)
                proto_iface.Addresses.extend(addrs)
                if ifstate == 'UP':
                    proto_iface.IfState = 1
                elif ifstate == 'DOWN':
                    proto_iface.IfState = 0
                else:
                    proto_iface.IfState = 2
                nl_ifaces.append(proto_iface)
            response.iface.extend(nl_ifaces)
            return response


    def GetExternalIfaces(self, request, context):
        with status.context(context):
            self.log.debug("Received external interface request")
            response = dataplane_pb2.ReplyIfaces()
            int_ifaces = []
            all_ifaces = self.nlGetIfaces()
            for neigh in request.Neighbours:
                int_tuple = self.nlGetIfaceFromNeigh(neigh)
                if int_tuple:
                    int_ifaces.append(int_tuple)
            ext_ifaces = [ iface for iface in all_ifaces if iface not in int_ifaces]
            nl_ifaces = []
            for iface in ext_ifaces:
                ifindex, ifname, ifstate = iface
                proto_iface = dataplane_pb2.Interface()
                proto_iface.IfName = ifname
                proto_iface.IfIndex = ifindex
                neighbours = self.nlGetNeighFromIface(ifindex)
                addrs = self.nlGetIfaceAddr(ifindex)
                proto_iface.Neighbours.extend(neighbours)
                proto_iface.Addresses.extend(addrs)
                if ifstate == 'UP':
                    proto_iface.IfState = 1
                elif ifstate == 'DOWN':
                    proto_iface.IfState = 0
                else:
                    proto_iface.IfState = 2
                nl_ifaces.append(proto_iface)
            response.iface.extend(nl_ifaces)
            return response


    def GetInternalIfaces(self, request, context):
        with status.context(context):
            self.log.debug("Received internal interface request")
            response = dataplane_pb2.ReplyIfaces()
            int_ifaces = []
            for neigh in request.Neighbours:
                int_tuple = self.nlGetIfaceFromNeigh(neigh)
                if int_tuple:
                    int_ifaces.append(int_tuple)
            nl_ifaces = []
            for iface in int_ifaces:
                ifindex, ifname, ifstate = iface
                proto_iface = dataplane_pb2.Interface()
                proto_iface.IfName = ifname
                proto_iface.IfIndex = ifindex
                neighbours = self.nlGetNeighFromIface(ifindex)
                addrs = self.nlGetIfaceAddr(ifindex)
                proto_iface.Neighbours.extend(neighbours)
                proto_iface.Addresses.extend(addrs)
                if ifstate == 'UP':
                    proto_iface.IfState = 1
                elif ifstate == 'DOWN':
                    proto_iface.IfState = 0
                else:
                    proto_iface.IfState = 2
                nl_ifaces.append(proto_iface)
            response.iface.extend(nl_ifaces)
            return response


    def GetRoutingTables(self, request, context):
        with status.context(context):
            self.log.debug("Received get routing table request!!!")
            response = dataplane_pb2.RoutesInAllTables()
            alltables = []
            routeTables = self.nlGetRoutingTables()
            for table, routes in routeTables.items():
                sroute_lst = []
                nroute_lst = []
                p_rt_tab = dataplane_pb2.RoutesInTable()
                p_rt_tab.table = int(table)
                for route in routes:
                    if 'segments' in route:
                        p_srv6 = dataplane_pb2.SRv6Route()
                        p_srv6.destination = route['destination']
                        p_srv6.encapmode = route['encapmode']
                        p_srv6.device = route['device']
                        p_srv6.table = route['table']
                        for seg in route['segments']:
                            srv6_segment = p_srv6.sr_path.add()
                            srv6_segment.segment = seg
                        sroute_lst.append(p_srv6)
                    else:
                        p_route = dataplane_pb2.Route()
                        p_route.destination = route['destination']
                        p_route.device = route['device']
                        p_route.nexthop = route['nexthop']
                        p_route.priority = route['priority']
                        p_route.table = route['table']
                        nroute_lst.append(p_route)
                p_rt_tab.route.extend(nroute_lst)
                p_rt_tab.SRoute.extend(sroute_lst)
                alltables.append(p_rt_tab)
            response.AllTables.extend(alltables)
            return response


    def GetRouteTable(self, request, context):
        with status.context(context):
            self.log.debug("Received a single route table dump request")
            response = dataplane_pb2.RoutesInTable()
            routeTables = self.nlGetRoutingTables()
            table = request.tableNo 
            routes = routeTables[table]
            sroute_lst = []
            nroute_lst = []
            for route in routes:
                if 'segments' in route:
                    p_srv6 = dataplane_pb2.SRv6Route()
                    p_srv6.destination = route['destination']
                    p_srv6.encapmode = route['encapmode']
                    p_srv6.device = route['device']
                    p_srv6.table = route['table']
                    for seg in route['segments']:
                        srv6_segment = p_srv6.sr_path.add()
                        srv6_segment.segment = seg
                    sroute_lst.append(p_srv6)
                else:
                    p_route = dataplane_pb2.Route()
                    p_route.destination = route['destination']
                    p_route.device = route['device']
                    p_route.nexthop = route['nexthop']
                    p_route.priority = route['priority']
                    p_route.table = route['table']
                    nroute_lst.append(p_route)
            response.table = int(table)
            response.route.extend(nroute_lst)
            response.SRoute.extend(sroute_lst)
            return response

    def Getip6tables(self, request, context):
        with status.context(context):
            self.log.debug("Received get IP6table request")
            response = dataplane_pb2.RequestIP6TableRule()
            rules_lst = []
            rules = iptc.easy.dump_chain('mangle', 'PREROUTING', ipv6=True)
            for rule in rules:
                p_rule = dataplane_pb2.IP6TableRule()
                p_rule.intName = rule['in-interface']
                p_rule.protocol = rule['protocol']
                proto = rule['protocol']
                port_details = rule[proto] 
                port_no = port_details['dport']
                p_rule.DPort = port_no
                hex_mark_str =  rule['target']['MARK']['set-xmark']
                split_hex_mark = hex_mark_str.split('/')
                int_mark = int(split_hex_mark[0], 16) 
                p_rule.FwmarkNo = int_mark
                rules_lst.append(p_rule)
            response.rules.extend(rules_lst)
            return response

    def nlGetRoutingTables(self):
        rTables = {}
        srv6_routes = []
        normal_routes = []
        table_lst = set()
        nlroutes = self.iproute.get_routes()
        for nlroute in nlroutes:
            dst_len = nlroute['dst_len']
            dst = nlroute.get_attr('RTA_DST', None)
            table = nlroute.get_attr('RTA_TABLE', None)
            nh = nlroute.get_attr('RTA_GATEWAY', None) 
            ifindex = nlroute.get_attr('RTA_OIF', None)
            priority = nlroute.get_attr('RTA_PRIORITY', None)
            srv6 = nlroute.get_attr('RTA_ENCAP', None)
            link = self.iproute.get_links(ifindex)
            d_ifname, ifname = link[0]['attrs'][0]
            table_lst.add(table)
            if srv6:
                sr = {}
                sr_dest = dst+'/'+str(dst_len)
                sr['destination'] = sr_dest
                
                msg_type, sr_details = srv6['attrs'][0]
                mode = sr_details['mode']
                segs = sr_details['segs']
                sr['segments'] = segs
                sr['encapmode'] = mode
                sr['device'] = ifname
                sr['table'] = table
                srv6_routes.append(sr)
            else:
                r = {}
                if (dst is None) and dst_len == 0:
                    ipaddr = ipaddress.ip_address(nh)
                    if ipaddr.version == 6:
                        dst = "::/0"
                    else:
                        dst = "0.0.0.0"
                    r['destination'] = dst
                else:
                    if dst_len != 0:
                        r['destination'] = dst+'/'+str(dst_len)
                    else:
                        r['destination'] = dst
                r['device'] = ifname
                r['priority'] = priority
                r['table']  = table
                if nh:
                    r['nexthop'] = nh
                    normal_routes.append(r)

        for tab in table_lst:
            tab_routes = []
            for route in normal_routes:
                if tab == route['table']:
                    tab_routes.append(route)

            for srroute in srv6_routes:
                if tab == srroute['table']:
                    tab_routes.append(srroute)
                    
            if len(tab_routes) == 0:
                continue

            rTables[tab] = tab_routes
        return rTables


    def nlGetIfaceFromNeigh(self, address): 
        ipaddr = ipaddress.ip_address(address)
        if ipaddr.version == 6:
            nei = self.iproute.get_neighbours(dst=address, family=AF_INET6)
        else:
            nei = self.iproute.get_neighbours(dst=address, family=AF_INET)
            
        if len(nei) == 0:
            return None

        ifindex = nei[0]['ifindex']
        link = self.iproute.get_links(ifindex)
        d_ifname, ifname = link[0]['attrs'][0]
        d_ifstate, ifstate = link[0]['attrs'][2]
        tup = (ifindex, ifname, ifstate)
        return tup

    def nlGetNeighFromIface(self, index):
        neigh_list = []
        neighbours = self.iproute.get_neighbours(ifindex=index, family=AF_INET6)
        for neigh in neighbours:
            addr = neigh.get_attr('NDA_DST', None)
            neigh_list.append(addr)
        return neigh_list
        
    
    def nlGetIfaceAddr(self, ind):
        addresses = []
        nladdrs = self.iproute.get_addr(index=ind)
        for nladdr in nladdrs: 
            addr = nladdr.get_attr('IFA_ADDRESS', None)
            prefix = nladdr['prefixlen'] 
            addr_str = addr+'/'+str(prefix)
            addresses.append(addr_str)
        return addresses


    def nlGetIfaces(self):
        links = self.iproute.get_links()
        ifaces = [] 
        for link in links:
            ifindex = link['index']
            ifname  = link.get_attr('IFLA_IFNAME', None)
            ifstate = link.get_attr('IFLA_OPERSTATE', None)
            tup = (ifindex, ifname, ifstate)
            ifaces.append(tup)
        return ifaces


class ConfigureDataplaneHandler(dataplaneapi_pb2_grpc.ConfigureDataplaneServicer):
    """gRPC request handler"""

    def __init__(self, _iproute):
        self.iproute = _iproute
        self.iptc = iptc
        self.last_route = 0
        self.log = logging.getLogger("ConfigureDataplaneHandler")
        self.tables = {}
        self.iptables = {}

    def FlowMark(self, request, context):
        with status.context(context):
            self.log.debug("Received request to create flow marks!!!")
            response = dataplane_pb2.ReplyFlowMark()
            succeeded = []
            failed = []
            for rule in request.rule:
                proto_rule = dataplane_pb2.IPRule()
                try:
                    out = self.iproute.rule('add',
                                    family=AF_INET6,
                                    table=rule.table,
                                    fwmark=rule.fwmark)
                except netlink.exceptions.NetlinkError as e:
                    if e.code == 17:
                        self.log.debug("Flow already added!!!")
                        continue
                proto_rule.table = rule.table
                proto_rule.fwmark = rule.fwmark
                msg, = out 
                err = msg['header']['error']
                if err:
                    failed.append(proto_rule)
                else:
                    succeeded.append(proto_rule)
            response.successful.extend(succeeded)
            if len(failed) == 0:
                response.applied = True
            else:
                response.applied = False
                response.failed.extend(failed)
            return response


    def CreateRouteTable(self, request, context):
        with status.context(context):
            self.log.debug("Received request to create routetable!!!!")
            response = dataplane_pb2.ReplyPARFlows()
            rtables = []
            failed = []
            self.log.debug("Request is type: %s"   %type(request))
            self.log.debug("Request: %s" %request)
            for flow in request.flow:
                rtab = dataplane_pb2.RTables()
                rtab.tableName = flow
                if flow not in self.tables:
                    if self.last_route == 0:
                        self.last_route = 10
                        self.log.debug("CreateRouteTable: About to create table %s for %s" %(self.last_route, flow))
                    rtab.tableNo = self.last_route
                    out = self.iproute.route("add", dst="::1",
                            oif=1, table=self.last_route)
                    msg, = out
                    err = msg['header']['error']
                    if err:
                        failed.append(flow)
                    else:
                        rtables.append(rtab)
                        self.tables[flow] = self.last_route
                        self.last_route += 1

            response.created.extend(rtables)

            if len(failed) == 0:
                response.CreatedAll = True
            else:
                response.CreatedAll = False
                response.flow.extend(failed)
            return response


    def AddIp6tableRule(self, request, context):
        with status.context(context):
            self.log.debug("Received request to add ip6table rules")
            self.log.debug("IP6Tables rules request received: %s" %request)
            response = dataplane_pb2.ReplyIP6TableRule()
            succeeded = []
            failed = []
            for rule in request.rules:
                self.log.debug("Processing rule %s" %rule)
                #if rule.protocol not in self.iptables:
                p_rule = dataplane_pb2.IP6TableRule()
                cmdlist = ['/sbin/ip6tables', '-t', 'mangle', '-A', 'PREROUTING', '-i', 'NULL', '-p', 'NULL', '--dport', 'NULL', '-j', 'MARK', '--set-mark', 'NULL']
                cmdlist[6] = rule.intName
                cmdlist[8] = rule.protocol
                cmdlist[10] = str(rule.DPort)
                cmdlist[14] = str(rule.FwmarkNo)
                self.log.debug("COMMAND to be applied: %s" %cmdlist)
                result = subprocess.run(cmdlist) 
                self.log.debug("Result of applying command: %s" %result)
                if result.returncode == 0:
                    succeeded.append(rule)
                    self.iptables[rule.protocol] = [rule.intName, rule.DPort, rule.FwmarkNo]
                else:
                    self.log.debug("Error code for adding table is %s" %result.returncode)
                    failed.append(rule)
            response.successful.extend(succeeded)
            if len(failed) == 0:
                response.ip6tablecreated = True
            else:
                response.ip6tablecreated = False 
                response.failed.extend(failed)
            return response
