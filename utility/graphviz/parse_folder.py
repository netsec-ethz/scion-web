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
import json
import os

# SCION
from lib.util import write_file

# GraphViz
from graphviz_lib import ASInformation

def get_topology_file(as_folder):
    """
    Looks for a topology file inside an AS folder, opens it
    and returns the opened file
    :param: string AS_folder: filepath to the AS folder
    :return: Topology dictionary
    """
    topology_file = ""
    # find topology file, just enter first br folder
    for directory in os.listdir(as_folder):
        if directory[:2] == 'br':
            for data in os.listdir(as_folder + "/" + directory):
                if data == 'topology.json':
                    topology_file = as_folder + "/" + directory + "/" + data
    # load topology json file
    with open(topology_file, 'r') as f:
        as_topo = json.load(f)
    return as_topo


def parse_as_folder(isd_number, as_number, as_folder):
    """
    Parses a AS folder to a nested dict
    :param: string ISD_number, string AS_number,string AS_folder: filepath to AS folder
    :return: Nested Dictionary with info from an AS folder
    """
    as_dict = {}
    as_topo = get_topology_file(as_folder)
    as_info = ASInformation(as_topo, isd_number, as_number)
    as_dict['name'] = as_info.name
    as_dict['core'] = as_info.core
    info_dict = {}
    info_dict["bs"] = as_info.bs_addr
    info_dict["cs"] = as_info.cs_addr
    info_dict["ps"] = as_info.ps_addr
    info_dict["zk"] = as_info.zk_addr
    as_dict['info'] = info_dict
    as_dict['intra_n'] = as_info.intra_isd_neighbors
    as_dict['inter_n'] = as_info.inter_isd_neighbors
    return as_dict


def parse_isd_folder(isd_number, isd_folder):
    """
    Parses a ISD folder to a nested dict
    :param: String ISD number, string ISD_folder: filepath to ISD folder
    :return: Nested Dictionary with info from an ISD folder
    """
    isd_dict = {}
    isd_dict['AS'] = {}
    inside_isd_folder = os.listdir(isd_folder)
    for directory in inside_isd_folder:
        if directory[:2] == 'AS':
            as_number = directory[2:]
            as_dict = parse_as_folder(isd_number, as_number, isd_folder + "/" + directory)
            isd_dict['AS'][as_number] = as_dict
    return isd_dict


def parse_gen_folder(gen_folder, output_path):
    """
    Parses a gen folder to a nested dict
    example gen folder: ISD1/AS2/,AS1/;ISD2/AS1/,AS3/
    ->
    dictionary {'ISD':{1:{'AS':{2:{..},1:{..}}2:{'AS':{1:{..}2:{..}}}
    :param: String gen_folder: filepath to the gen folder
    :return: Nested Dictionary with all the information to draw the graph
    """
    gen_dict = {}
    gen_dict['ISD'] = {}
    inside_gen_folder = os.listdir(gen_folder)
    for directory in inside_gen_folder:
        if directory[:3] == 'ISD':
            isd_number = directory[3:]
            isd_dict = parse_isd_folder(isd_number, gen_folder + "/" + directory)
            gen_dict['ISD'][isd_number] = isd_dict
    write_file(os.path.join(output_path, 'output.json'),
               json.dumps(gen_dict, sort_keys=True, indent=4))
    return gen_dict

def parse_desc_labels(labels_file):
    try:
        with open(labels_file, 'r') as f:
            data = json.load(f)
    except ValueError:
        print ('Warning: Decoding label file failed. Creating graph without labels.')
        return {"ISD": {}, "AS": {}}
    except FileNotFoundError:
        print ('Warning: Label file not found. Creating graph without labels.')
        return {"ISD": {}, "AS": {}}
    
    if 'ISD' not in data:
        print ('Warning: ISD labels missing. Adding AS labels only.')
        data["ISD"] = {}
    if 'AS' not in data:
        print ('Warning: AS labels missing. Adding ISD labels only.')
        data["AS"] = {}
    return data
