# Copyright 2016 ETH Zurich
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
import configparser
import json
import os
from collections import defaultdict

# External packages
from django.shortcuts import get_object_or_404

# SCION
from lib.defines import (BEACON_SERVICE,
                         CERTIFICATE_SERVICE,
                         PATH_SERVICE,
                         ROUTER_SERVICE,
                         SIBRA_SERVICE,
                         PROJECT_ROOT)
from lib.packet.scion_addr import ISD_AS

# SCION-WEB
from ad_manager.models import AD


ZOOKEEPER_SERVICE = "zk"  # TODO: make PR to add into lib.defines as it used to
WEB_ROOT = os.path.join(PROJECT_ROOT, 'sub', 'web')

SUPPORTED_CLOUD_ENGINES = ['switch_engines', 'amazon_ec2']

TYPES_TO_SERVICES = {
    'router': ROUTER_SERVICE,
    'beacon_server': BEACON_SERVICE,
    'path_server': PATH_SERVICE,
    'cert_server': CERTIFICATE_SERVICE,
    'sibra_server': SIBRA_SERVICE,
    'zookeeper_service': ZOOKEEPER_SERVICE
}


def add_new_section(config, section_name):
    try:
        config.add_section(section_name)
    except configparser.DuplicateSectionError:
        pass  # section already exists


def fill_section(config, section_name, val, tags, hostname_lookup, simple_mode):
    server_index = 0
    add_new_section(config, section_name)
    for (serv_id, entry) in val:
        server_index += 1
        entry = entry.split('/')[0]  # remove subnet size
        try:
            hostname = hostname_lookup[entry]
        except KeyError:
            hostname = serv_id  # no hostname defined, use identifier
        if simple_mode:
            entry = 'localhost'
        config[section_name][entry] = tags + '={} # {}'.format(server_index,
                                                               hostname)


def fill_router_section(config, section_name, val, isd_id, as_id, simple_mode):
    """
    Fills in the router section of the Ansible hostfile.
    Each line in this section has a list of dictionaries for the set of routers
    running on the host. An example looks like the following:
    127.0.0.1 isd=1 as=1 instances='["1", "7"]' # ['br1-1-1', 'br1-1-7']
    :param ConfigParser config: Hostfile configuration to be filled in
    :param str section_name: The name of the section (e.g. border_routers)
    :param list val: A list of tuples (router_name, address)
    :param str isd_id: the ISD the service belongs to.
    :param str as_id: the AS the service belongs to.
    """
    add_new_section(config, section_name)
    addr2instances = defaultdict(list)
    addr2name = defaultdict(list)
    for router_name, addr in val:
        if simple_mode:
            addr = 'localhost'
        else:
            # remove subnet if exists
            addr = addr.split('/')[0]
        # extract the instance id from the router name
        _, _, instance_id = router_name[2:].split('-')
        addr2instances[addr].append(instance_id)
        addr2name[addr].append(router_name)

    for addr, instances in addr2instances.items():
        config[section_name][addr] = "isd=%s as=%s instances='%s' # %s" % \
                                     (isd_id, as_id, json.dumps(instances),
                                      addr2name[addr])


def set_cloud_providers(config, topology_params):
    try:
        addresses = topology_params.getlist('inputCloudAddress')
        providers = topology_params.getlist('inputCloudEngine')
        for provider in SUPPORTED_CLOUD_ENGINES:
            if provider in providers:
                add_new_section(config, provider)
                # a direct mask would be more efficient
                section_values = filter(
                    None, map(lambda matched:
                              matched[0] if matched[1] == provider else None,
                              zip(addresses, providers)
                              )
                )
                for ip in section_values:
                    config.set(provider, ip)
    except KeyError:
        # There are no IPs with a selected cloud provider so the previous
        # section is superfluous
        pass


def get_section_addr(topo_dict, section_name):
    """
    Extract all the service types and their corresponding addresses.
    : param dict topo_dict: the topology dictionary.
    : param str section_name: the name of the service (e.g. BeaconService)
    : returns: a list of pairs of the service type and addresse.
    """
    section = topo_dict[section_name]
    ret_val = []
    if section_name == 'ZookeeperService':
        for sec_id in section:
            ret_val.append((sec_id, section[sec_id]['Addr']))
    elif section_name.endswith('Service'):
        for sec_id in section:
            for addr_idx in range(len(section[sec_id]['Public'])):
                ret_val.append((sec_id, section[sec_id]['Public'][addr_idx]['Addr']))
    elif section_name.endswith("Routers"):
        for sec_id in section:
            int_addrs = section[sec_id]['InternalAddrs']
            for int_addr_idx in range(len(int_addrs)):
                for addr_idx in range(len(int_addrs[int_addr_idx]['Public'])):
                    ret_val.append((sec_id, int_addrs[int_addr_idx]['Public'][addr_idx]['Addr']))
    return ret_val


def generate_ansible_hostfile(topology_params, topo_dict, isd_as,
                              commit_hash):
    """
    Generate the host file for Ansible
    The hostfile is per AS and can have the same IP in multiple roles
    """
    # Write Ansible hostfile
    config = configparser.ConfigParser(allow_no_value=True, delimiters=' ',
                                       inline_comment_prefixes='#')
    isd_id, as_id = ISD_AS(isd_as)
    as_obj = get_object_or_404(AD, isd_id=isd_id, as_id=as_id)
    host_file_path = os.path.join(WEB_ROOT, 'gen',
                                  'ISD' + str(isd_id), 'AS' + str(as_id),
                                  'host.{}-{}'.format(isd_id, as_id))
    scion_nodes = []  # entries for the scion_node section
    for key, service_type in [('BeaconService', 'beacon_server'),
                              ('CertificateService', 'cert_server'),
                              ('BorderRouters', 'router'),
                              ('PathService', 'path_server'),
                              ('SibraService', 'sibra_server'),
                              ('ZookeeperService', 'zookeeper_service')]:
        val = get_section_addr(topo_dict, key)
        if not val:  # skip empty entries
            continue
        hostnames = topology_params.getlist('inputHostname')
        unique_addr = topology_params.getlist('inputCloudAddress')
        hostname_lookup = dict(zip(unique_addr, hostnames))
        if service_type.endswith('_server'):
            section_name = service_type + 's'
            tags = 'isd=%s as=%s %s' % (isd_id, as_id,
                                        TYPES_TO_SERVICES[service_type])
            fill_section(config, section_name, val, tags, hostname_lookup,
                         as_obj.simple_conf_mode)
        elif service_type == 'router':
            section_name = 'border_routers'
            fill_router_section(config, section_name, val, isd_id, as_id,
                                as_obj.simple_conf_mode)
        elif service_type == 'zookeeper_service':
            section_name = 'zookeepers'
            tags = 'isd=%s as=%s %s' % (isd_id, as_id,
                                        TYPES_TO_SERVICES[service_type])
            fill_section(config, section_name, val, tags, hostname_lookup,
                         as_obj.simple_conf_mode)
            continue  # zookeepers are not to be listed in scion_nodes children
        scion_nodes.append(section_name)

    add_new_section(config, 'scion_nodes:children')
    for role in scion_nodes:
        config.set('scion_nodes:children', role)

    # set cloud providers sections
    set_cloud_providers(config, topology_params)

    # environment variables
    add_new_section(config, 'scion_nodes:vars')
    local_gen_path = os.path.join(WEB_ROOT, 'gen')
    config.set('scion_nodes:vars', 'local_gen={}'.format(local_gen_path))
    config.set('scion_nodes:vars', 'scion_version={}'.format(commit_hash))

    with open(host_file_path, 'w') as configfile:
        config.write(configfile, space_around_delimiters=False)
