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

# External packages
from django.test import TestCase

# SCION-WEB
from ad_manager.models import AD, ISD
from ad_manager.util.ad_connect import (
    CORE_CONNECTION,
    PARENT_CHILD_CONNECTION,
    PEER_CONNECTION,
    link_ads,
)
# SCION
from lib.types import LinkType


class TestLinkAds(TestCase):
    """
    Functional tests for ad_manager.util.ad_connect.link_ads
    """
    def test_basic(self):
        isd = ISD.objects.create(id=1)
        ip_addresses = []
        as_id = 1
        test_connections = {
            CORE_CONNECTION: [LinkType.CORE, LinkType.CORE],
            PEER_CONNECTION: [LinkType.PEER, LinkType.PEER],
            PARENT_CHILD_CONNECTION: [LinkType.CHILD, LinkType.PARENT],
        }
        for connection in test_connections.keys():
            ad1 = AD.objects.create(isd=isd, as_id=as_id)
            ad2 = AD.objects.create(isd=isd, as_id=as_id+1)
            link_ads(ad1, ad2, connection)

            ad1_routers = list(ad1.routerweb_set.all())
            ad2_routers = list(ad2.routerweb_set.all())
            assert len(ad1_routers) == 1
            assert len(ad2_routers) == 1

            router1 = ad1.routerweb_set.all()[0]
            router2 = ad2.routerweb_set.all()[0]

            assert router1.neighbor_isd_id == ad2.isd.id
            assert router1.neighbor_as_id == ad2.as_id
            assert router2.neighbor_isd_id == ad1.isd.id
            assert router2.neighbor_as_id == ad1.as_id

            # Check addresses
            assert router1.interface_toaddr == router2.interface_addr
            assert router2.interface_toaddr == router1.interface_addr

            # Check ports
            assert router1.interface_toport == router2.interface_port
            assert router2.interface_toport == router1.interface_port

            neighbor_type1, neighbor_type2 = test_connections[connection]
            assert router1.neighbor_type == neighbor_type1
            assert router2.neighbor_type == neighbor_type2

            ip_addresses += [router1.addr, router1.interface_addr,
                             router2.addr, router2.interface_addr]
            as_id = as_id + 2

        # Check that there are no IP duplicates
        assert len(ip_addresses) == len(set(ip_addresses))
