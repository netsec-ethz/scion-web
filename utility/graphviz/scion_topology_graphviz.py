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
import sys
import os
import argparse
import random
from graphviz import Graph
from graphviz import Source

# SCION
from lib.packet.scion_addr import ISD_AS

# GraphViz
from graphviz_lib import IsdGraph
from parse_folder import parse_gen_folder, parse_desc_labels

def draw_isd_graph(ISD, AS_list, ip_addresses, location_labels, labels):
    """
    Draws an ISD graph.
    :param: string ISD number, array AS_list: list of ASes in the isd
            boolean edge_labels: indicates if edge labels are drawn
            boolean ip_addresses: indicates if node labels are drawn
            dict labels: Dictionary containing labels for ISDs and ASes
    :return: Dot graph: ISD graph
    """
    graph_lib = IsdGraph(ISD, AS_list)
    isd_graph = graph_lib.get_graph(location_labels, labels)
    # sort ASes by core and non-core
    core_AS_list = graph_lib.sort_ASes()['core']
    non_core_AS_list = graph_lib.sort_ASes()['non-core']
    # add all core nodes in a core graph
    core_graph = graph_lib.get_core_graph()
    graph_lib.add_nodes(core_AS_list, core_graph, True, ip_addresses, location_labels, labels)
    isd_graph.subgraph(core_graph)
    # add all non core nodes
    graph_lib.add_nodes(non_core_AS_list, isd_graph, False, ip_addresses, location_labels, labels)
    # add all edges to the graph from core to leaf,
    # order is important such that core ASes end up on top
    c_neighbors = core_AS_list
    n_neighbors = graph_lib.draw_edges_from_current(c_neighbors, isd_graph, ip_addresses)
    # loop while some nodes dont have all their edges, add edges of nodes in current neighbors,
    # add nodes to next neighbors if they are not in ASes done,
    # not in next neighbors yet and not in current neighbors
    while len(n_neighbors) > 0:
        c_neighbors = n_neighbors
        n_neighbors = graph_lib.draw_edges_from_current(c_neighbors, isd_graph, ip_addresses)
    return isd_graph


def draw_inter_ISD_edges(scion_graph, ISDs, node_labels):
    """
    Draws all the inter ISD edges.
    :param: graphviz scion_graph: graph of the topology,
            array ISDs: list of isds in the topology
            boolean edge_labels: boolean indicating if edge labels are drawn
    :return: Dot graph: modified topology graph
    """
    ISDs_done = []
    # go through each ISD and draw its inter-ISD edges
    for ISD in ISDs:
        ISDs_done.append(ISD)
        AS_list = ISDs[ISD]["AS"]
        # for each AS draw its inter-ISD edges
        for AS in AS_list:
            if len(AS_list[AS]["inter_n"]) > 0:
                draw_edges_for_as(ISDs, ISD, AS, ISDs_done, node_labels, scion_graph)
    return scion_graph


def draw_edges_for_as(ISDs, ISD, AS, ISDs_done, node_labels, scion_graph):
    AS_list = ISDs[ISD]["AS"]
    ia = "%s-%s" % (ISD, AS)
    for interface in AS_list[AS]["inter_n"]:
        neighborISD = AS_list[AS]["inter_n"][interface]["n_isd"]
        neighborAS = AS_list[AS]["inter_n"][interface]["n_as"]
        # check if neighbor ISD was already handled
        if AS_list[AS]["inter_n"][interface]["n_isd"] not in ISDs_done:
            # check if neighbor exists (in case it is referenced but folder does not exist)
            if neighborISD not in ISDs:
                continue
            if neighborAS not in ISDs[neighborISD]["AS"]:
                continue
            n_ia = "%s-%s" % (neighborISD, neighborAS)
            if node_labels:
                color = get_color()
                remote = get_remote_interface(ISDs[neighborISD]["AS"][neighborAS], AS_list[AS]["inter_n"][interface]["br-ip"], \
                    AS_list[AS]["inter_n"][interface]["br-port"])
                headlabel = '<<font color="' + color + '">' + str(remote[0]) + ": " + str(remote[1]) + '</font>>' 
                taillabel = '<<font color="' + color + '">' + str(interface) + ': ' + \
                    str(AS_list[AS]["inter_n"][interface]["br-port"]) + '</font>>' 
                scion_graph.edge(ia, n_ia, color=color,
                                     _attributes={'constraint': 'false', 'headlabel': headlabel,
                                                  'taillabel': taillabel})
            else:
                scion_graph.edge(ia, n_ia)

def get_remote_interface(AS_dict, ip, port):
    """
    Given an AS Border Router interface, the corresponding interface on the other side of the link is returned
    """
    for interface in AS_dict["inter_n"]:
        if AS_dict["inter_n"][interface]["remote-ip"] == ip:
            if AS_dict["inter_n"][interface]["remote-port"] == port:
                return (interface, port)
    return ('','')

def get_color():
    """
    Returns a random color from a selection to be used for an edge
    """
    colors = ['green', 'gold', 'indigo', 'orangered', 'crimson', \
        'magenta', 'darkslategray', 'greenyellow', 'hotpink', 'lightsalmon']
    return random.choice(colors)

def draw_SCION_topology(topology_dict, n_labels, l_labels, desc_labels):
    """
    Draws the Scion topology from a topology dictionary
    returned by parse_gen_folder.
    :param dictionary topology_dict: dictionary returned by parse_gen_folder,
            boolean ip_addresses: indicates if node labels are drawn,
            boolean edge_labels: indicates if edge labels are drawn
            dict desc_labels: Dictionary containing labels for ISDs and ASes
    :return Dot graph: graph of the SCION topology
    """
    isd_graphs = {}
    dot = Graph(name='topology',filename='topology.gv',comment='SCION-net')
    ISDs = topology_dict["ISD"]
    # draw each ISD graph
    for ISD in ISDs:
        isd_graphs[ISD] = draw_isd_graph(ISD, ISDs[ISD]["AS"], n_labels, l_labels, desc_labels)
    # put all isd graphs into the same graph
    for ISD in isd_graphs:
        dot.subgraph(isd_graphs[ISD])
    # add edges between ISDs
    dot = draw_inter_ISD_edges(dot, ISDs, n_labels)
    return dot

def main():
    """
    Draws the topology of the SCION network in a gen folder.
    example: python scion_topology_graph -g "gen", -e, -n:
    will place a pdf file of the scion topology with edge and node labels
    into output/scion_topo.gv
    -g: path to the gen folder ex: SCION/gen
    -n: set this flag if address/port information should be drawn
    -l: set this flag if location labels should be drawn
    -o: path to the output file ex: output/scion_topo.gv
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-gp', '--gen_folder_path', default="gen",
                        help='path to the gen folder')
    parser.add_argument('-lp', '--label_file_path', default="",
                        help='path to the gen folder')
    parser.add_argument('-n', '--node_labels', action='store_true', default=False,
                        help='set this flag to add address/port information')
    parser.add_argument('-l', '--location_labels', action='store_true', default=False,
                        help='set this flag if add location labels')
    parser.add_argument('-o', '--output_path', default="output/scion_topo.gv",
                        help='path to the output topology file')
    args = parser.parse_args()

    if os.path.exists(args.gen_folder_path):
        topo = parse_gen_folder(args.gen_folder_path, args.output_path)
    else:
        print ('Error: No gen folder found at ' + args.gen_folder_path)
        return

    if args.location_labels:
        labels = parse_desc_labels(args.label_file_path)
    else:
        labels = {}
    dot = draw_SCION_topology(topo, args.node_labels, args.location_labels, labels)
    s = Source(dot, filename=dot.filename, format="pdf")
    s.render(directory=args.output_path)

if __name__ == '__main__':
    main()
