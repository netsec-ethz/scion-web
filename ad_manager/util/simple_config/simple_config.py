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
import os
from string import Template

# External packages
from django.shortcuts import get_object_or_404

# SCION
from lib.util import read_file

# SCION-WEB
from ad_manager.models import (
    AD,
    ConnectionRequest,
)


SIMPLE_CONF_OVERLAY_TYPE = 'UDP/IPv4'
SIMPLE_CONF_DIR = os.path.dirname(os.path.abspath(__file__))
SimpleConfTemplate = Template(read_file(
    os.path.join(SIMPLE_CONF_DIR, "simple_config_topo.tmpl")))


def prep_simple_conf_con_req(as_obj, topo_dict, user):
    """
    Creates the connection request object based on the simple topo values
    and saves it into the database.
    :param AD as_obj: The database object of the AS.
    :param topo_dict: Topology as a dictionary object.
    :param User user: Django user.
    :returns: Connection request object.
    :rtype: ConnectionRequest
    """
    router_name = 'br%s-%s-1' % (as_obj.isd_id, as_obj.as_id)
    router = topo_dict['BorderRouters'][router_name]
    interface = router['Interfaces']['1']
    con_req = ConnectionRequest.objects.create(
        created_by=user,
        connect_to=interface['ISD_AS'],
        connect_from=as_obj,
        router_info='%s:%s' % (interface['Public']['Addr'], interface['Public']['L4Port']),
        overlay_type=SIMPLE_CONF_OVERLAY_TYPE,
        router_public_ip=interface['Public']['Addr'],
        router_public_port=interface['Public']['L4Port'],
        mtu=interface['MTU'],
        bandwidth=interface['Bandwidth'],
        link_type=interface['LinkType'],
        info='Hello from SCIONLab User Simple Setup')
    return con_req


def check_simple_conf_mode(topo_dict, isd_id, as_id):
    """
    Checks if the AS is in simple mode and updates the simple_conf_mode
    accordingly.
    """
    services = ['BeaconService', 'CertificateService', 'PathService', 'SibraService']
    as_obj = get_object_or_404(AD, isd_id=isd_id, as_id=as_id)
    service_addrs = set()
    for service in services:
        for _, service_instance in topo_dict[service].items():
            for addr_idx in range(len(service_instance['Public'])):
                service_addrs.add(service_instance['Public'][addr_idx]['Addr'])
    br_addrs = set()
    for _, br_instance in topo_dict['BorderRouters'].items():
        for br_int_addrs in br_instance['InternalAddrs']:
            for addr_idx in range(len(br_int_addrs['Public'])):
                br_addrs.add(br_int_addrs['Public'][addr_idx]['Addr'])
    zk_addrs = set()
    for _, zk_instance in topo_dict['ZookeeperService'].items():
        zk_addrs.add(zk_instance['Addr'])
    if (len(service_addrs) == 1 and len(zk_addrs) == 1 and
            '127.0.0.1' in zk_addrs):
        as_obj.simple_conf_mode = True
    else:
        as_obj.simple_conf_mode = False
    as_obj.save()
