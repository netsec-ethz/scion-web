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
import argparse
from graphviz import Graph
from graphviz import Source

# SCION
from graphviz_lib import IsdGraph
from parse_folder import parse_gen_folder
from lib.packet.scion_addr import ISD_AS


def draw_isd_graph(ISD, AS_list, edge_labels, ip_addresses):
    """
    Draws an ISD graph.
    :param: string ISD number, array AS_list: list of ASes in the isd
            boolean edge_labels: indicates if edge labels are drawn
            boolean ip_addresses: indicates if node labels are drawn
    :return: Dot graph: ISD graph
    """
    graph_lib = IsdGraph(ISD, AS_list)
    isd_graph = graph_lib.get_graph()
    # sort ASes by core and non-core
    core_AS_list = graph_lib.sort_ASes()['core']
    non_core_AS_list = graph_lib.sort_ASes()['non-core']
    # add all core nodes in a core graph
    core_graph = graph_lib.get_core_graph()
    graph_lib.add_nodes(core_AS_list, core_graph, True, ip_addresses)
    isd_graph.subgraph(core_graph)
    # add all non core nodes
    graph_lib.add_nodes(non_core_AS_list, isd_graph, False, ip_addresses)
    # add all edges to the graph from core to leaf,
    # order is important such that core ASes end up on top
    c_neighbors = core_AS_list
    n_neighbors = graph_lib.draw_edges_from_current(c_neighbors, isd_graph, edge_labels)
    # loop while some nodes dont have all their edges, add edges of nodes in current neighbors,
    # add nodes to next neighbors if they are not in ASes done,
    # not in next neighbors yet and not in current neighbors
    while len(n_neighbors) > 0:
        c_neighbors = n_neighbors
        n_neighbors = graph_lib.draw_edges_from_current(c_neighbors, isd_graph, edge_labels)
    return isd_graph


def draw_inter_ISD_edges(scion_graph, ISDs, edge_labels):
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
                draw_edges_for_as(ISDs, ISD, AS, ISDs_done, edge_labels, scion_graph)
    return scion_graph


def draw_edges_for_as(ISDs, ISD, AS, ISDs_done, edge_labels, scion_graph):
    """
    Draws all the inter ISD edges for a list of ASes.
    :param: string ISD: ISD of the AS, string AS: AS number of the AS,
            array AS_list: contains information of the AS,
            graphviz scion_graph: graph of the topology,
            array ISDs_done: array of ISDs whose inter isd edges have been drawn,
            array ISDs: list of ISDs,
            boolean edge_labels: indicates if edge labels are drawn
    """
    AS_list = ISDs[ISD]["AS"]
    ia = ISD_AS.from_values(ISD, AS)
    id = ia.__str__()
    for neighbor_ISD in AS_list[AS]["inter_n"]:
        if neighbor_ISD not in ISDs_done:
            for neighbor in AS_list[AS]["inter_n"][neighbor_ISD]:
                # check if neighbor exits
                o_as = ISDs[ISD]["AS"][AS]["inter_n"]
                n_as = ISDs[neighbor_ISD]["AS"][neighbor]["inter_n"]
                if neighbor_ISD not in ISDs:
                    continue
                if neighbor not in ISDs[neighbor_ISD]["AS"]:
                    continue
                n_ia = ISD_AS.from_values(neighbor_ISD,neighbor)
                neighbor_id = n_ia.__str__()
                if edge_labels:
                    taillabel = str(o_as[neighbor_ISD][neighbor]["br-id"])
                    headlabel = str(n_as[ISD][AS]["br-id"])
                    scion_graph.edge(id, neighbor_id,
                                     _attributes={'constraint': 'false', 'headlabel': headlabel,
                                                  'taillabel': taillabel})
                else:
                    scion_graph.edge(id, neighbor_id, _attributes={'constraint': 'false'})


def draw_SCION_topology(topology_dict, n_labels, e_labels):
    """
    Draws the Scion topology from a topology dictionary
    returned by parse_gen_folder.
    :param dictionary topology_dict: dictionary returned by parse_gen_folder,
            boolean ip_addresses: indicates if node labels are drawn,
            boolean edge_labels: indicates if edge labels are drawn
    :return Dot graph: graph of the SCION topology
    """
    isd_graphs = {}
    dot = Graph(name='topology',filename='topology.gv',comment='SCION-net')
    ISDs = topology_dict["ISD"]
    # draw each ISD graph
    for ISD in ISDs:
        isd_graphs[ISD] = draw_isd_graph(ISD, ISDs[ISD]["AS"], e_labels, n_labels)
    # put all isd graphs into the same graph
    for ISD in isd_graphs:
        dot.subgraph(isd_graphs[ISD])
    # add edges between ISDs
    dot = draw_inter_ISD_edges(dot, ISDs, e_labels)
    return dot


def main():
    """
    Draws the topology of the SCION network in a gen folder.
    example: python scion_topology_graph -g "gen", -e, -n:
    will place a pdf file of the scion topology with edge and node labels
    into output/scion_topo.gv
    -g: path to the gen folder ex: SCION/gen
    -e: set this flag if edge labels should be drawn
    -n: set this flag if node labels should be drawn
    -o: path to the output file ex: output/scion_topo.gv
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--gen_folder_path', default="gen",
                        help='path to the gen folder')
    parser.add_argument('-e', '--edge_labels', action='store_true', default=False,
                        help='set this flag if you want edge labels')
    parser.add_argument('-n', '--node_labels', action='store_true', default=False,
                        help='set this flag if you want node labels')
    parser.add_argument('-o', '--output_path', default="output/scion_topo.gv",
                        help='path to the output topology file')
    args = parser.parse_args()
    topo = parse_gen_folder(args.gen_folder_path)
    dot = draw_SCION_topology(topo, args.node_labels, args.edge_labels)
    s = Source(dot, filename=dot.filename, format="pdf")
    s.render(directory=args.output_path)

if __name__ == '__main__':
    main()
