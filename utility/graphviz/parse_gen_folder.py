#parses the gen folder to a nested dictionary.

import json
import os
from lib import AS_information

# get a topology file inside one of the border-router folders and open it
def get_topoology_file(AS_folder):

    topology_file = ""
    # find topology file, just enter first br folder
    for directory in os.listdir(AS_folder):
        if directory[:2] == 'br':
            for data in os.listdir(AS_folder + "/" + directory):

                if data == 'topology.json':
                    topology_file = AS_folder + "/" + directory + "/" + data

    # load topology json file
    with open(topology_file, 'r') as f:
        AS_topo = json.load(f)

    return AS_topo

# parse an AS folder
def parse_AS_folder(ISD_number, AS_number, AS_folder):

    AS_dict = {}

    AS_topo = get_topoology_file(AS_folder)

    AS_info = AS_information(AS_topo, ISD_number, AS_number)

    AS_dict['name'] = AS_info.name
    AS_dict['core'] = AS_info.core

    info_dict = {}
    info_dict["bs"] = AS_info.bs_addr
    info_dict["cs"] = AS_info.cs_addr
    info_dict["ps"] = AS_info.ps_addr
    info_dict["zk"] = AS_info.zk_addr

    AS_dict['info'] = info_dict

    AS_dict['Intra_ISD_neighbors'] = AS_info.intra_isd_neighbors
    AS_dict['Inter_ISD_neighbors'] = AS_info.inter_isd_neighbors

    return AS_dict

#parse an ISD folder
def parse_ISD_folder(ISD_number, ISD_folder):

    ISD_dict = {}

    ISD_dict['AS'] = {}

    inside_ISD_folder = os.listdir(ISD_folder)

    for directory in inside_ISD_folder:

        if directory[:2] == 'AS':

            AS_number = directory[2:]

            AS_dict = parse_AS_folder(ISD_number, AS_number, ISD_folder + "/" + directory)

            ISD_dict['AS'][AS_number] = AS_dict




    return ISD_dict

#parse a gen folder to a nested dictionary with all the information to draw the graph
def parse_gen_folder(gen_folder):

    gen_dict = {}

    gen_dict['ISD'] = {}

    inside_gen_folder = os.listdir(gen_folder)

    for directory in inside_gen_folder:

        if directory[:3] == 'ISD':

            ISD_number = directory[3:]

            ISD_dict = parse_ISD_folder(ISD_number,gen_folder + "/" + directory)

            gen_dict['ISD'][ISD_number] = ISD_dict

    with open('output.cfg', 'w') as outfile:
        json.dump(gen_dict,outfile)

    return gen_dict

