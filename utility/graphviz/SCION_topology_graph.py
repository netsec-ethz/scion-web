#Takes a gen folder and uses graphviz to draw a diagram of the topology. Configure if you want edge labes/node labels. Not Supported : Does not parse multiple links between ASes.

from graphviz import Graph
import parse_gen_folder
import sys
from lib import ISD_graph
# Creates a graphviz graph from an input scion topology file (json).

# draw the ISD graph
def draw_isd_graph(ISD, AS_list, edge_labels, ip_addresses):

    graph_lib = ISD_graph(ISD, AS_list)

    isd_graph = graph_lib.get_graph()

    # sort ASes by core and non-core
    core_AS_list = graph_lib.sort_ASes_core()['core']
    non_core_AS_list = graph_lib.sort_ASes_core()['non-core']

    # add all core nodes in a core graph
    core_graph = graph_lib.get_core_graph()
    graph_lib.add_nodes(core_AS_list, core_graph, True, ip_addresses )
    isd_graph.subgraph(core_graph)
    # add all non core nodes
    graph_lib.add_nodes(non_core_AS_list, isd_graph, False, ip_addresses)

    # add all edges to the graph from core to leaf, order is important such that core ASes end up on top
    current_neighbors = core_AS_list

    next_neighbors = graph_lib.draw_edges_from_current(current_neighbors, isd_graph, edge_labels)

    # loop while some nodes dont have all their edges, add edges of nodes in current neighbors, add nodes to next neighbors if they are not in ASes done, not in next neighbors yet and not in current neighbors
    while len(next_neighbors)>0 :
        current_neighbors = next_neighbors
        next_neighbors = graph_lib.draw_edges_from_current(current_neighbors, isd_graph, edge_labels)


    return isd_graph

# draw edges between ISDs
def draw_inter_ISD_edges(scion_graph, ISDs, edge_labels):

    ISDs_done = []

    #go through each ISD and draw its inter-ISD edges
    for ISD in ISDs:

        ISD_prefix = ISD + "-"

        ISDs_done.append(ISD)

        AS_list = ISDs[ISD]["AS"]

        # for each AS draw its inter-ISD edges
        for AS in AS_list:

            id = ISD_prefix + AS

            if len(AS_list[AS]["Inter_ISD_neighbors"])>0:
                for neighbor_ISD in AS_list[AS]["Inter_ISD_neighbors"]:
                    if neighbor_ISD not in ISDs_done:
                        for neighbor in AS_list[AS]["Inter_ISD_neighbors"][neighbor_ISD]:
                            # check if neighbor exits
                            if neighbor_ISD not in ISDs:
                                continue
                            print ISDs[neighbor_ISD]["AS"]
                            if neighbor not in ISDs[neighbor_ISD]["AS"]:
                                continue
                            neighbor_id = neighbor_ISD + "-" + neighbor

                            taillabel = ISDs[ISD]["AS"][AS]["Inter_ISD_neighbors"][neighbor_ISD][neighbor]["br-id"]
                            headlabel = ISDs[neighbor_ISD]["AS"][neighbor]["Inter_ISD_neighbors"][ISD][AS]["br-id"]

                            taillabel = str(taillabel)
                            headlabel = str(headlabel)

                            if edge_labels:
                                scion_graph.edge(id, neighbor_id,
                                               _attributes={'constraint':'false','headlabel': headlabel, 'taillabel': taillabel})
                            else:
                                scion_graph.edge(id, neighbor_id,
                                                 _attributes={'constraint': 'false'})

    return scion_graph

# Input topology dictionary , Output graphviz topology
def draw_SCION_topology(topology_file, ip_addresses, edge_labels):

    # variables
    isd_graphs = {}

    dot = Graph(comment='SCION-net')

    ISDs = topology_file["ISD"]

    # draw each ISD graph
    for ISD in ISDs:
        isd_graphs[ISD] = draw_isd_graph(ISD, topology_file["ISD"][ISD]["AS"], edge_labels, ip_addresses)

    # put all isd graphs into the same graph
    for ISD in isd_graphs:
        dot.subgraph(isd_graphs[ISD])

    # add edges between ISDs
    dot = draw_inter_ISD_edges(dot, ISDs, edge_labels)

    return dot


# Command line: string "directory of gen folder", boolean draw ip addresses?, boolean draw edge labels ?
def main():

    for arg in sys.argv[1:]:
        print arg

    gen_folder_path = sys.argv[1:][0]
    ip_addresses = sys.argv[1:][1]
    edge_labels = sys.argv[1:][2]

    if edge_labels == "True":
        edge_labels = True
    else:
        edge_labels = False

    if ip_addresses == "True":
        ip_addresses = True
    else:
        ip_addresses = False

    topo = parse_gen_folder.parse_gen_folder(gen_folder_path)
    dot = draw_SCION_topology(topo, ip_addresses, edge_labels)
    print(dot.source)
    dot.render('test-output/scion_topo.gv', view=True)

if __name__ == '__main__':
    main()

