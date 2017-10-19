from graphviz import Graph

class AS_information(object):

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
        self.intra_isd_neighbors = self.get_neighbors()['intra-ISD']
        self.inter_isd_neighbors = self.get_neighbors()['inter-ISD']

    def get_AS_name(self):

        name = ""
        for item in self.topology:
            if item == "name":
                name = item

        return name

    def get_bs_addr(self):

        bs_addr = ""
        # only save one ip address  !multiple beaconservice ip addresses not supported!
        for item in self.topology["BeaconService"]:
            bs_addr = self.topology["BeaconService"][item]["Public"][0]["Addr"]
            break

        return bs_addr

    def get_cs_addr(self):

        cs_addr = ""
        # only save one ip address  !multiple beaconservice ip addresses not supported!
        for item in self.topology["CertificateService"]:
            cs_addr = self.topology["CertificateService"][item]["Public"][0]["Addr"]
            break

        return cs_addr

    def get_ps_addr(self):

        ps_addr = ""
        # only save one ip address  !multiple beaconservice ip addresses not supported!
        for item in self.topology["PathService"]:
            ps_addr = self.topology["PathService"][item]["Public"][0]["Addr"]
            break

        return ps_addr

    def get_zk_addr(self):

        zk_addr = ""
        # only save one ip address  !multiple beaconservice ip addresses not supported!
        for item in self.topology["ZookeeperService"]:
            zk_addr = self.topology["ZookeeperService"][item]["Addr"]
            break

        return zk_addr

    def get_core_bool(self):

        return self.topology["Core"]

    def get_neighbors(self):

        intra_isd_neighbor_dict = {}
        inter_isd_neighbor_dict = {}

        for border_router in self.topology["BorderRouters"]:

            neighbor_IA = self.get_neighbor_IA_interface(border_router)['IA']
            interface = self.get_neighbor_IA_interface(border_router)['interface']
            neighbor_ISD = self.get_ISD_AS(neighbor_IA)['ISD']
            neighbor_AS = self.get_ISD_AS(neighbor_IA)['AS']

            if neighbor_ISD == self.ISD:
                intra_isd_neighbor = {'br-id': interface, 'br-ip':
                    self.topology["BorderRouters"][border_router]["Interfaces"][interface]["Public"]["Addr"]}
                intra_isd_neighbor_dict[neighbor_AS] = intra_isd_neighbor

            else:
                inter_isd_neighbor = {'br-id': interface, 'br-ip':
                    self.topology["BorderRouters"][border_router]["Interfaces"][interface]["Public"]["Addr"]}
                if neighbor_ISD not in inter_isd_neighbor_dict:
                    inter_isd_neighbor_dict[neighbor_ISD] = {}
                inter_isd_neighbor_dict[neighbor_ISD][neighbor_AS] = inter_isd_neighbor

        return {'intra-ISD':intra_isd_neighbor_dict, 'inter-ISD': inter_isd_neighbor_dict}

    def get_neighbor_IA_interface(self, border_router):

        interface = ""
        neighbor_IA = ""
        # extract neighbor IA for this border router
        for item in self.topology["BorderRouters"][border_router]["Interfaces"]:
            neighbor_IA = self.topology["BorderRouters"][border_router]["Interfaces"][item]["ISD_AS"]
            interface = item
            break

        return {'IA':neighbor_IA, 'interface': interface}

    def get_ISD_AS(self, IA):

        neighbor_ISD = ""
        for k in IA:
            if k == "-":
                break
            else:
                neighbor_ISD = neighbor_ISD + k
        k = len(neighbor_ISD) + 1
        neighbor_AS = IA[k:]

        return {'ISD': neighbor_ISD, 'AS': neighbor_AS}

class ISD_graph(object):

    def __init__(self, ISD, AS_list):

        self.ISD = ISD
        self.ISD_prefix = self.ISD + "-"
        self.ASes_done = []
        self.AS_list = AS_list

    def get_graph(self):

        graph_name = 'cluster_' + "ISD " + self.ISD
        label = "ISD " + self.ISD
        isd_graph = Graph(name=graph_name, graph_attr={'color': 'blue', 'label': label, 'style': 'rounded'})

        return isd_graph

    def get_core_graph(self):

        return Graph(name='cluster_core', graph_attr={'color': 'red', 'label': '','style': 'rounded'})

    def add_nodes(self, to_draw_list, core_graph, core, ip_addresses):

        for AS in to_draw_list:

            if ip_addresses:
                self.draw_node_with_attributes(AS, core, core_graph)
            else:
                self.draw_node_without_attributes(AS, core, core_graph)

    def sort_ASes_core(self):

        core_AS_list = []
        non_core_AS_list = []
        for AS in self.AS_list:
            if self.AS_list[AS]["core"]:
                core_AS_list.append(AS)
            else:
                non_core_AS_list.append(AS)

        return {'core': core_AS_list, 'non-core': non_core_AS_list}

    def draw_node_without_attributes(self, AS, core, graph):

        node_id = self.ISD + "-" + AS
        node_name = self.AS_list[AS]["name"]
        node_name = self.ISD_prefix + AS + node_name + " (core)"

        if core:
            node_name = node_name + " (core)"

        graph.node(node_id, node_name, _attributes={'shape': 'box'})

    def draw_node_with_attributes(self, AS, core, graph):

        node_id = self.ISD + "-" + AS
        node_name = self.AS_list[AS]["name"]
        node_name = self.ISD_prefix + AS + node_name + " (core)"

        if core:
            node_name = node_name + " (core)"

        node_name = node_name + "\n"
        node_attributes = self.get_node_attr(self.AS_list[AS], AS, self.ISD_prefix)
        print node_attributes.assemble_string()
        node_name = node_name + node_attributes.assemble_string()

        graph.node(node_id, node_name, _attributes={'shape': 'box'})

    def draw_edges_from_current(self, current_neighbors, graph, edge_labels):

        next_neighbors = []

        for AS in current_neighbors:
            self.ASes_done.append(AS)
            id = self.ISD_prefix + AS
            for neighbor in self.AS_list[AS]["Intra_ISD_neighbors"]:
                # check if neighbor exists
                if neighbor not in self.AS_list:
                    continue
                # check if we have not drawn edges for the neighbor
                if neighbor not in self.ASes_done:
                    neighbor_id = self.ISD_prefix + neighbor
                    taillabel = self.AS_list[AS]["Intra_ISD_neighbors"][neighbor]["br-id"]
                    headlabel = self.AS_list[neighbor]["Intra_ISD_neighbors"][AS]["br-id"]

                    taillabel = str(taillabel)
                    headlabel = str(headlabel)
                    if edge_labels:
                        graph.edge(id, neighbor_id, _attributes={'headlabel': headlabel, 'taillabel': taillabel})
                    else:
                        graph.edge(id, neighbor_id)
                    # add node to next rotation if not in current/next
                    if neighbor not in current_neighbors:
                        if neighbor not in next_neighbors:
                            next_neighbors.append(neighbor)

        return next_neighbors

    class get_node_attr(object):

        def __init__(self, AS, AS_number, ISD_prefix):

            # ex: info_dict[br] = ip address of br
            # ex: reverse_info_dict[1.3.3.3] = ['zk', 'bs']
            self.info_dict = {}
            self.reverse_info_dict = {}
            self.AS = AS
            self.AS_number = AS_number
            self.ISD_prefix = ISD_prefix

            self.gather_non_br_info()
            self.gather_intra_br_info()
            self.gather_inter_br_info()
            self.info_string = self.assemble_string

        def gather_non_br_info(self):

            for info in self.AS["info"]:

                self.info_dict[info] = self.AS["info"][info]
                if self.AS["info"][info] not in self.reverse_info_dict:
                    self.reverse_info_dict[self.AS["info"][info]] = [info]
                else:
                    self.reverse_info_dict[self.AS["info"][info]].append(info)

        def gather_intra_br_info(self):

            # gather addresses of intra ISD border routers
            for neighbor in self.AS["Intra_ISD_neighbors"]:

                br_id = str(self.AS["Intra_ISD_neighbors"][neighbor]["br-id"])

                self.info_dict["br" + self.ISD_prefix + "-" + br_id] = self.AS["Intra_ISD_neighbors"][neighbor]["br-ip"]
                if self.AS["Intra_ISD_neighbors"][neighbor]["br-ip"] not in self.reverse_info_dict:
                    self.reverse_info_dict[self.AS["Intra_ISD_neighbors"][neighbor]["br-ip"]] = ["br" + self.ISD_prefix + "-" + br_id]
                else:
                    self.reverse_info_dict[self.AS["Intra_ISD_neighbors"][neighbor]["br-ip"]].append(
                        "br" + self.ISD_prefix + "-" + br_id)


        def gather_inter_br_info(self):

            # gather addresses of inter ISD border routers
            for neighbor_ISD in self.AS["Inter_ISD_neighbors"]:

                for neighbor in self.AS["Inter_ISD_neighbors"][neighbor_ISD]:

                    br_id = str(self.AS["Inter_ISD_neighbors"][neighbor_ISD][neighbor]["br-id"])

                    self.info_dict["br" + self.ISD_prefix + "-" + br_id] = self.AS["Inter_ISD_neighbors"][neighbor_ISD][neighbor][
                        "br-ip"]
                    if self.AS["Inter_ISD_neighbors"][neighbor_ISD][neighbor]["br-ip"] not in self.reverse_info_dict:
                        self.reverse_info_dict[self.AS["Inter_ISD_neighbors"][neighbor_ISD][neighbor]["br-ip"]] = [
                            "br" + self.ISD_prefix + "-" + br_id]
                    else:
                        self.reverse_info_dict[self.AS["Inter_ISD_neighbors"][neighbor_ISD][neighbor]["br-ip"]].append(
                            "br" + self.ISD_prefix + "-" + br_id)


        def assemble_string(self):

            info_string = ""

            printed = []
            printed_ip = []
            for key in self.info_dict:
                ip_address = self.info_dict[key]
                for node in self.reverse_info_dict[ip_address]:
                    if node not in printed:
                        printed.append(node)

                        info_string = info_string + node + ","

                if ip_address not in printed_ip:
                    printed_ip.append(ip_address)
                    info_string = info_string[:-1]
                    info_string = info_string + ": " + ip_address + "\n"

            return info_string



