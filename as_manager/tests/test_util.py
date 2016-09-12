# External packages
from django.test import TestCase

# SCION
from as_manager.models import AS, ISD
from as_manager.util.ad_connect import link_ases


class TestLinkAds(TestCase):
    """
    Functional tests for as_manager.util.ad_connect.link_ases
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
            ad1 = AS.objects.create(isd=isd, as_id=1)
            ad2 = AS.objects.create(isd=isd, as_id=2)
            link_ases(ad1, ad2, link_type)

            ad1_routers = list(ad1.routerweb_set.all())
            ad2_routers = list(ad2.routerweb_set.all())
            assert len(ad1_routers) == 1
            assert len(ad2_routers) == 1

            router1 = ad1.routerweb_set.all()[0]
            router2 = ad2.routerweb_set.all()[0]

            assert router1.neighbor_as == ad2
            assert router2.neighbor_as == ad1

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
