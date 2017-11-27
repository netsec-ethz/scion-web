# Copyright 2017 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Stdlib
from graphviz import Graph

# SCION
from lib.packet.scion_addr import ISD_AS


class ASInformation(object):
    """
    Class to represent all information of an AS
    """
    def __init__(self, topology, ISD, AS):
        self.AS = AS
        self.ISD = ISD
        self.topology = topology
        self.name = self.get_AS_name()
        self.bs_addr = self.get_bs_addr()
        self.ps_addr = self.get_ps_addr()
        self.cs_addr = self.get_cs_addr()
        self.zk_addr = self.get_zk_addr()
        self.core = self.get_core_bool()
        self.intra_isd_neighbors = self.get_neighbors()['intra']
        self.inter_isd_neighbors = self.get_neighbors()['inter']

    def get_AS_name(self):
        """
        :return: String: Name of the AS
        """
        name = ""
        for item in self.topology:
            if item == "name":
                name = item
        return name

    def get_bs_addr(self):
        """
        :return: String: Address of the bs
        """
        # TODO(@philippmao: add support for multiple bs)
        bs_id = list(self.topology["BeaconService"].keys())[0]
        bs_addr = self.topology["BeaconService"][bs_id]["Public"][0]["Addr"]
        return bs_addr

    def get_cs_addr(self):
        """
        :return: String: Address of the cs
        """
        # TODO(@philippmao: add support for multiple cs)
        cs_id = list(self.topology["CertificateService"].keys())[0]
        cs_addr = self.topology["CertificateService"][cs_id]["Public"][0]["Addr"]
        return cs_addr

    def get_ps_addr(self):
        """
        :return: String: Address of the ps
        """
        # TODO(@philippmao: add support for multiple ps)
        ps_id = list(self.topology["PathService"].keys())[0]
        ps_addr = self.topology["PathService"][ps_id]["Public"][0]["Addr"]
        return ps_addr

    def get_zk_addr(self):
        """
        :return: String: Address of the zk
        """
        # TODO(@philippmao: add support for multiple zk)
        zk_id = list(self.topology["ZookeeperService"].keys())[0]
        zk_addr = self.topology["ZookeeperService"][zk_id]["Addr"]
        return zk_addr

    def get_core_bool(self):
        """
        :return: Boolean: True if AS is core, False if not
        """
        return self.topology["Core"]

    def get_neighbors(self):
        """
        :return: Nested dictionary with intra and inter isd neighbor dictionaries
        """
        intra_dict = {}
        inter_dict = {}
        border_routers = self.topology["BorderRouters"]
        for br in border_routers:
            neighbor_IA = self.get_neighbor_IA_interface(br)['IA']
            ie = self.get_neighbor_IA_interface(br)['interface']
            n_isd = str(self.get_ISD_AS(neighbor_IA)._isd)
            n_as = str(self.get_ISD_AS(neighbor_IA)._as)
            if n_isd == self.ISD:
                intra_isd_neighbor = \
                    {'br-id': ie, 'br-ip': border_routers[br]["Interfaces"][ie]["Public"]["Addr"]}
                intra_dict[n_as] = intra_isd_neighbor
            else:
                inter_isd_neighbor = \
                    {'br-id': ie, 'br-ip': border_routers[br]["Interfaces"][ie]["Public"]["Addr"]}
                if n_isd not in inter_dict:
                    inter_dict[n_isd] = {}
                inter_dict[n_isd][n_as] = inter_isd_neighbor
        return {'intra': intra_dict, 'inter': inter_dict}

    def get_neighbor_IA_interface(self, br):
        """
        :param:  br: Border router string
        :return: A dictionary with the neighbor IA and interface
                 of the border router connected to that IA
        """
        interface = ""
        neighbor_IA = ""
        # extract neighbor IA for this border router
        brs = self.topology["BorderRouters"]
        for item in brs[br]["Interfaces"]:
            neighbor_IA = brs[br]["Interfaces"][item]["ISD_AS"]
            interface = item
            break
        return {'IA': neighbor_IA, 'interface': interface}

    def get_ISD_AS(self, IA):
        """
        :param: self, string IA ex: "1-4"
        :return ISD_AS object
        """
        ia = ISD_AS(raw=IA)
        ia._parse_str(IA)
        return ia


class IsdGraph(object):
    """
    Class to represent all information of an ISD graph
    """
    def __init__(self, ISD, AS_list):
        self.ISD = ISD
        self.ASes_done = []
        self.AS_list = AS_list

    def get_graph(self):
        """
        :return: Isd graphviz graph with correct formatting
        """
        graph_name = 'cluster_' + "ISD " + self.ISD
        label = "ISD " + self.ISD
        isd_graph = Graph(name=graph_name,
                          graph_attr={'color': 'blue', 'label': label, 'style': 'rounded'})
        return isd_graph

    def get_core_graph(self):
        """
        :return: Isd graphviz core graph with correct formatting
        """
        return Graph(name='cluster_core',
                     graph_attr={'color': 'red', 'label': '', 'style': 'rounded'})

    def add_nodes(self, to_draw_list, graph, core, ip_addresses):
        """
        Adds nodes of ASes to a graph
        :param: self, array to_draw_list: an array of ASes,
                graphviz graph: Graph to which we add the nodes,
                bool core: indicates if we add core nodes
                bool ip_addresses: indicates if we have edge labels
        """
        for AS in to_draw_list:
            if ip_addresses:
                self.draw_node_with_attributes(AS, core, graph)
            else:
                self.draw_node_without_attributes(AS, core, graph)

    def sort_ASes(self):
        """
        Sorts core and non-core ASes.
        :return: Dict with core and non core Ases.
        """
        core_AS_list = []
        non_core_AS_list = []
        for AS in self.AS_list:
            if self.AS_list[AS]["core"]:
                core_AS_list.append(AS)
            else:
                non_core_AS_list.append(AS)
        return {'core': core_AS_list, 'non-core': non_core_AS_list}

    def draw_node_without_attributes(self, AS, core, graph):
        """
        Adds a node without any attributes to the graph.
        :param: self, string AS: AS ID, boolean core: inidicates if the AS is core
                graphviz graph: graph to which we add the AS
        """
        ia = ISD_AS.from_values(self.ISD, AS)
        node_id = ia.__str__()
        node_name = self.AS_list[AS]["name"]
        node_name = ia.__str__() + node_name
        if core:
            node_name = node_name + " (core)"
        graph.node(node_id, node_name, _attributes={'shape': 'box'})

    def draw_node_with_attributes(self, AS, core, graph):
        """
        Adds a node with attributes to the graph.
        :param: self, string AS: AS ID, boolean core: inidicates if the AS is core
                graphviz graph: graph to which we add the AS
        """
        ia = ISD_AS.from_values(self.ISD, AS)
        node_id = ia.__str__()
        node_name = self.AS_list[AS]["name"]
        node_name = ia.__str__() + node_name
        if core:
            node_name = node_name + " (core)"
        node_name = node_name + "\n"
        node_attributes = self.NodeAttributes(self.AS_list[AS], AS, self.ISD)
        node_name = node_name + node_attributes.assemble_string()
        graph.node(node_id, node_name, _attributes={'shape': 'box'})

    def draw_edges_from_current(self, current_neighbors, graph, edge_labels):
        """
        Adds edges for all ASes in current_neighbors
        :param: self, array of ASes: list of ASes whose edges we draw,
                graphviz graph: graph to which we add the edges,
                boolean edge_labels: boolean indicating if we add labels to the edges
        """
        next_neighbors = []
        for AS in current_neighbors:
            self.ASes_done.append(AS)
            ia = ISD_AS.from_values(self.ISD, AS)
            id = ia.__str__()
            for neighbor in self.AS_list[AS]["intra_n"]:
                n_dict = self.AS_list[AS]["intra_n"][neighbor]
                # check if neighbor exists
                if neighbor not in self.AS_list:
                    continue
                # check if we have not drawn edges for the neighbor
                if neighbor not in self.ASes_done:
                    n_ia = ISD_AS.from_values(self.ISD, neighbor)
                    n_id = n_ia.__str__()
                    if edge_labels:
                        headlabel = str(self.AS_list[neighbor]["intra_n"][AS]["br-id"])
                        taillabel = str(n_dict["br-id"])
                        graph.edge(id, n_id,
                                   _attributes={'headlabel': headlabel, 'taillabel': taillabel})
                    else:
                        graph.edge(id, n_id)
                    # add node to next rotation if not in current/next
                    if neighbor not in current_neighbors:
                        if neighbor not in next_neighbors:
                            next_neighbors.append(neighbor)
        return next_neighbors

    class NodeAttributes(object):
        """
        Class to collect all attributes of an AS (br,ps,bs ..)
        """
        def __init__(self, AS, AS_number, ISD):
            # ex: info_dict[br] = ip address of br
            # ex: reverse_info_dict[1.3.3.3] = ['zk', 'bs']
            self.info_dict = {}
            self.rev_info_dict = {}
            self.AS = AS
            self.AS_n = AS_number
            self.ISD = ISD
            self.IA = ISD_AS.from_values(self.ISD, self.AS_n)
            self.gather_non_br_info()
            self.gather_intra_br_info()
            self.gather_inter_br_info()
            self.info_string = self.assemble_string

        def gather_non_br_info(self):
            """
            Gathers info for all non border router elements
            and writes the info to the info and reverse info dict.
            """
            for info in self.AS["info"]:
                self.info_dict[info] = self.AS["info"][info]
                if self.AS["info"][info] not in self.rev_info_dict:
                    self.rev_info_dict[self.AS["info"][info]] = [info]
                else:
                    self.rev_info_dict[self.AS["info"][info]].append(info)

        def gather_intra_br_info(self):
            """
            Gathers info for all intra isd border router elements
            and writes the info to the info and reverse info dict.
            """
            for neighbor in self.AS["intra_n"]:
                n_dict = self.AS["intra_n"][neighbor]
                br_id = str(n_dict["br-id"])
                self.info_dict["br" + self.IA.__str__() + "-" + br_id] = n_dict["br-ip"]
                if n_dict["br-ip"] not in self.rev_info_dict:
                    self.rev_info_dict[n_dict["br-ip"]] = \
                        ["br" + self.IA.__str__() + "-" + br_id]
                else:
                    self.rev_info_dict[n_dict["br-ip"]].append(
                        "br" + self.IA.__str__() + "-" + br_id)

        def gather_inter_br_info(self):
            """
            Gathers info for all inter isd border router elements
            and writes the info to the info and reverse info dict.
            """
            for neighbor_ISD in self.AS["inter_n"]:
                n_dict = self.AS["inter_n"][neighbor_ISD]
                for neighbor in n_dict:
                    n_isd = n_dict[neighbor]
                    br_id = str(n_isd["br-id"])
                    self.info_dict["br" + self.IA.__str__() + "-" + br_id] = n_isd["br-ip"]
                    if n_isd["br-ip"] not in self.rev_info_dict:
                        self.rev_info_dict[n_isd["br-ip"]] = \
                            ["br" + self.IA.__str__() + "-" + br_id]
                    else:
                        self.rev_info_dict[n_isd["br-ip"]].append(
                            "br" + self.IA.__str__() + "-" + br_id)

        def assemble_string(self):
            """
            Builds the string for the node label from
            the info in the info dict and reverse info dict
            """
            info_string = ""
            printed = []
            printed_ip = []
            for key in self.info_dict:
                ip_address = self.info_dict[key]
                for node in self.rev_info_dict[ip_address]:
                    if node not in printed:
                        printed.append(node)
                        info_string = info_string + node + ","
                if ip_address not in printed_ip:
                    printed_ip.append(ip_address)
                    info_string = info_string[:-1]
                    info_string = info_string + ": " + ip_address + "\n"
            return info_string
