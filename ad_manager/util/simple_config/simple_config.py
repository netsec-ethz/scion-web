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

# SCION
from lib.util import read_file

# SCION-WEB
from ad_manager.models import ConnectionRequest


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
    interface = router['Interface']
    con_req = ConnectionRequest.objects.create(
        created_by=user,
        connect_to=interface['ISD_AS'],
        connect_from=as_obj,
        router_info='%s:%s' % (interface['Addr'], interface['UdpPort']),
        overlay_type=SIMPLE_CONF_OVERLAY_TYPE,
        router_public_ip=interface['Addr'],
        router_public_port=interface['UdpPort'],
        mtu=interface['MTU'],
        bandwidth=interface['Bandwidth'],
        link_type=interface['LinkType'],
        info='Hello from SCIONLab User Simple Setup')
    return con_req
