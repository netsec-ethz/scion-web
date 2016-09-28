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

# SCION
from ad_manager.models import AD, ISD
from ad_manager.util.ad_connect import link_ads


class TestLinkAds(TestCase):
    """
    Functional tests for ad_manager.util.ad_connect.link_ads
    """
    def test_basic(self):
        isd = ISD.objects.create(id=1)

        link_types = {
            'ROUTING': ['ROUTING', 'ROUTING'],
            'PEER': ['PEER', 'PEER'],
            'PARENT_CHILD': ['CHILD', 'PARENT'],
        }

        ip_addresses = []
        for link_type in link_types.keys():
            ad1 = AD.objects.create(isd=isd)
            ad2 = AD.objects.create(isd=isd)
            link_ads(ad1, ad2, link_type)

            ad1_routers = list(ad1.routerweb_set.all())
            ad2_routers = list(ad2.routerweb_set.all())
            assert len(ad1_routers) == 1
            assert len(ad2_routers) == 1

            router1 = ad1.routerweb_set.all()[0]
            router2 = ad2.routerweb_set.all()[0]

            assert router1.neighbor_ad == ad2
            assert router2.neighbor_ad == ad1

            # Check addresses
            assert router1.interface_toaddr == router2.interface_addr
            assert router2.interface_toaddr == router1.interface_addr

            # Check ports
            assert router1.interface_toport == router2.interface_port
            assert router2.interface_toport == router1.interface_port

            neighbor_type1, neighbor_type2 = link_types[link_type]
            assert router1.neighbor_type == neighbor_type1
            assert router2.neighbor_type == neighbor_type2

            ip_addresses += [router1.addr, router1.interface_addr,
                             router2.addr, router2.interface_addr]

        # Check that there are no IP duplicates
        assert len(ip_addresses) == len(set(ip_addresses))
