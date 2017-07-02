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
import copy
import logging

# External packages
import jsonfield
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.db import models, IntegrityError

# SCION
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DEFAULT_MTU,
    PATH_SERVICE,
    SIBRA_SERVICE,
)
from lib.packet.scion_addr import ISD_AS

# SCION-WEB
from ad_manager.util.common import empty_dict
from ad_manager.util.defines import (
    ADDR_ATTRIBUTES,
    DEFAULT_BANDWIDTH,
    SCION_SUGGESTED_PORT,
)

PORT = SCION_SUGGESTED_PORT
PACKAGE_DIR_PATH = 'gen'


class SelectRelatedModelManager(models.Manager):
    """
    Model manager that also selects related objects from the database,
    avoiding multiple similar queries.
    """

    def get_queryset(self):
        queryset = super(SelectRelatedModelManager, self).get_queryset()
        related_fields = getattr(self.model, 'related_fields', [])
        if not related_fields:
            return queryset.select_related()
        else:
            return queryset.select_related(*related_fields)


class OrganisationAdmin(models.Model):
    user = models.OneToOneField(User)
    is_org_admin = models.BooleanField(default=False)
    account_id = models.CharField(max_length=260, null=False, blank=True)
    secret = models.CharField(max_length=260, null=False, blank=True)


class ISD(models.Model):
    id = models.IntegerField(primary_key=True)

    def get_absolute_url(self):
        return reverse('isd_detail', args=[self.id])

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name = 'ISD'
        ordering = ['id']


class AD(models.Model):
    as_id = models.IntegerField(default=-1)
    isd = models.ForeignKey('ISD')
    is_core_ad = models.BooleanField(default=False)
    simple_conf_mode = models.BooleanField(default=False)
    is_open = models.BooleanField(default=True)
    md_host = models.GenericIPAddressField(default='127.0.0.1')
    original_topology = jsonfield.JSONField(default=empty_dict)
    sig_pub_key = models.CharField(max_length=100, null=True, blank=True)
    sig_priv_key = models.CharField(max_length=100, null=True, blank=True)
    enc_pub_key = models.CharField(max_length=100, null=True, blank=True)
    enc_priv_key = models.CharField(max_length=100, null=True, blank=True)
    master_as_key = models.CharField(max_length=100, null=True, blank=True)
    certificate = models.TextField(null=True, blank=True)
    trc = models.TextField(null=True, blank=True)

    # Use custom model manager with select_related()
    objects = SelectRelatedModelManager()

    class Meta:
        unique_together = (("as_id", "isd"),)
        verbose_name = 'AD'
        ordering = ['as_id']

    def generate_topology_dict(self):
        """
        Create a Python dictionary with the stored AS topology.
        """
        assert isinstance(self.original_topology, dict)
        out_dict = copy.deepcopy(self.original_topology)
        out_dict.update({
            'ISDID': int(self.isd_id), 'ADID': int(self.as_id),
            'Core': int(self.is_core_ad),
            'BorderRouters': {}, 'PathService': {}, 'BeaconService': {},
            'CertificateService': {}, 'SibraService': {},
        })
        for router in self.borderrouter_set.all():
            out_dict['BorderRouters'][router.name] = router.get_dict()
        for service in self.service_set.all():
            if service.name.startswith('bs'):
                out_dict['BeaconService'][service.name] = service.get_dict()
            elif service.name.startswith('ps'):
                out_dict['PathService'][service.name] = service.get_dict()
            elif service.name.startswith('cs'):
                out_dict['CertificateService'][service.name] = service.get_dict()
            elif service.name.startswith('sb'):
                out_dict['SibraService'][service.name] = service.get_dict()
        return out_dict

    def get_all_elements(self):
        element_groups = [self.borderrouter_set.all(), self.service_set.all()]
        for element_group in element_groups:
            for element in element_group:
                yield element

    def get_all_element_ids(self):
        all_elements = self.get_all_elements()
        element_ids = [element.id_str() for element in all_elements]
        return element_ids

    def fill_router_info(self, router_dict):
        """
        Update the router information in the database.
        (i.e., BorderRouter and BorderRouterAddress.)
        :param dict router_dict: topo_dict['BorderRouters']
        """
        for name, router in router_dict.items():
            br_obj, _ = BorderRouter.objects.update_or_create(name=name, ad=self)
            br_addr_idx = []
            for router_addr in router['InternalAddrs']:
                for addr_attr in ADDR_ATTRIBUTES:
                    if addr_attr not in router_addr.keys():
                        continue
                    for addr_idx, addr_info in enumerate(router_addr[addr_attr]):
                        addr = addr_info['Addr']
                        port = addr_info['L4Port']
                        if not port:
                            port = router_addr['Public'][addr_idx]['L4Port']
                        # TODO (ercanucan): currently we assume IPv4
                        addr_type = 'IPv4'
                        br_addr_obj, _ = BorderRouterAddress.objects.update_or_create(
                            addr=addr,
                            l4port=port,
                            addr_type=addr_type,
                            is_public=(addr_attr == 'Public'),
                            router=br_obj,
                            ad=self
                        )
                        br_addr_idx.append(br_addr_obj)
            for if_id, intf in router["Interfaces"].items():
                isd_id, as_id = ISD_AS(intf["ISD_AS"])
                br_addr_obj = br_addr_idx[intf['InternalAddrIdx']]
                br_inft_obj, _ = BorderRouterInterface.objects.update_or_create(
                    addr=intf['Public']['Addr'],
                    l4port=intf['Public']['L4Port'],
                    remote_addr=intf['Remote']['Addr'],
                    remote_l4port=intf['Remote']['L4Port'],
                    internal_addr_idx=intf['InternalAddrIdx'],
                    interface_id=if_id,
                    bandwidth=intf['Bandwidth'],
                    mtu=intf['MTU'],
                    neighbor_isd_id=isd_id,
                    neighbor_as_id=as_id,
                    neighbor_type=intf["LinkType"],
                    router_addr=br_addr_obj,
                    ad=self
                )
                if 'Bind' in intf.keys():
                    br_inft_obj.update(
                        bind_addr=intf['Bind']['Addr'],
                        bind_l4port=intf['Bind']['L4Port'],
                    )

    def fill_service_info(self, service_dict):
        """
        Update the service information in the database.
        (i.e., Service and ServiceAddress tables.)
        :param dict service_dict: (e.g., topo_dict['BeaconService'])
        """
        for name, service in service_dict.items():
            srv_obj, _ = Service.objects.update_or_create(name=name, ad=self)
            for addr_attr in ADDR_ATTRIBUTES:
                if addr_attr not in service.keys():
                    continue
                for addr_idx, addr_info in enumerate(service[addr_attr]):
                    addr = addr_info["Addr"]
                    port = addr_info["L4Port"]
                    if not port and addr_attr is 'Bind':
                        port = service['Public'][addr_idx]['L4Port']
                    # TODO (ercanucan): currently we assume IPv4
                    addr_type = 'IPv4'
                    srv_addr_obj, _ = ServiceAddress.objects.update_or_create(
                        addr=addr,
                        l4port=port,
                        addr_type=addr_type,
                        is_public=(addr_attr == 'Public'),
                        service=srv_obj,
                        ad=self
                    )

    def fill_from_topology(self, topology_dict, clear=False, auto_refs=False):
        """
        Add infrastructure elements (servers, routers) to the AD, extracted
        from the topology dictionary.
        """
        assert isinstance(topology_dict, dict), 'Dictionary expected'

        if clear:
            self.borderrouter_set.all().delete()
            self.borderrouteraddress_set.all().delete()
            self.borderrouterinterface_set.all().delete()
            self.service_set.all().delete()
            self.serviceaddress_set.all().delete()

        self.original_topology = topology_dict
        self.is_core_ad = (topology_dict['Core'] == 1)
        self.save()

        routers = topology_dict["BorderRouters"]
        beacon_servers = topology_dict["BeaconService"]
        certificate_servers = topology_dict["CertificateService"]
        path_servers = topology_dict["PathService"]
        sibra_servers = topology_dict["SibraService"]

        try:
            self.fill_router_info(routers)
            self.fill_service_info(beacon_servers)
            self.fill_service_info(certificate_servers)
            self.fill_service_info(path_servers)
            self.fill_service_info(sibra_servers)

        except IntegrityError:
            logging.warning("Integrity error in AD.fill_from_topology(): "
                            "ignoring")
            raise

    def get_absolute_url(self):
        return reverse('ad_detail', args=[self.as_id])

    def get_full_process_name(self, id_str):
        if ':' in id_str:
            return id_str
        else:
            # changed for rpc log retrieval, to match new supervisord names
            return "as{}-{}:{}".format(self.isd.id, self.as_id, id_str)

    def __str__(self):
        return '{}-{}'.format(self.isd.id, self.as_id)


class AddressElement(models.Model):
    addr = models.GenericIPAddressField()
    l4port = models.IntegerField(default=-1)
    overlay_port = models.IntegerField(null=True)
    addr_type = models.CharField(max_length=5, default="IPv4")
    is_public = models.BooleanField(default=True)
    ad = models.ForeignKey(AD)

    class Meta:
        abstract = True


class Service(models.Model):
    ad = models.ForeignKey(AD)
    name = models.CharField(max_length=20, null=True)


class ServiceAddress(AddressElement):
    service = models.ForeignKey(Service)


class BorderRouter(models.Model):
    ad = models.ForeignKey(AD)
    name = models.CharField(max_length=20, null=True)


class BorderRouterAddress(AddressElement):
    router = models.ForeignKey(BorderRouter)


class BorderRouterInterface(models.Model):
    addr = models.GenericIPAddressField()
    l4port = models.IntegerField(default=-1)
    bind_addr = models.GenericIPAddressField(default=None, null=True)
    bind_l4port = models.IntegerField(default=None, null=True)
    remote_addr = models.GenericIPAddressField(null=True)
    remote_l4port = models.IntegerField(null=True)
    internal_addr_idx = models.IntegerField()
    interface_id = models.IntegerField()
    bandwidth = models.IntegerField()
    mtu = models.IntegerField()
    NEIGHBOR_TYPES = (
        ('CHILD',) * 2,
        ('PARENT',) * 2,
        ('PEER',) * 2,
        ('CORE',) * 2,
    )
    neighbor_isd_id = models.IntegerField(null=True)
    neighbor_as_id = models.IntegerField(null=True)
    neighbor_type = models.CharField(max_length=10, choices=NEIGHBOR_TYPES)
    router_addr = models.ForeignKey(BorderRouterAddress)
    ad = models.ForeignKey(AD)


class SCIONWebElement(models.Model):
    addr = models.GenericIPAddressField()
    port = models.IntegerField()
    addr_internal = models.GenericIPAddressField(default=None, null=True)
    port_internal = models.IntegerField(default=None, null=True)
    ad = models.ForeignKey(AD)
    name = models.CharField(max_length=20, null=True)

    def id_str(self):
        # FIXME How to identify multiple servers of the same type?
        # return "{}{}-{}-{}".format(self.prefix, self.ad.isd_id,
        #                           self.ad_id, self.name)
        return self.name

    def get_dict(self):
        return {'AddrType': 'IPV4', 'Addr': self.addr}

    def __str__(self):
        return '{} -- {}'.format(self.ad, self.addr)

    class Meta:
        abstract = True


class BeaconServerWeb(SCIONWebElement):
    prefix = BEACON_SERVICE

    class Meta:
        verbose_name = 'Beacon server'
        unique_together = (("ad", "addr", "port"),)


class CertificateServerWeb(SCIONWebElement):
    prefix = CERTIFICATE_SERVICE

    class Meta:
        verbose_name = 'Certificate server'
        unique_together = (("ad", "addr", "port"),)


class PathServerWeb(SCIONWebElement):
    prefix = PATH_SERVICE

    class Meta:
        verbose_name = 'Path server'
        unique_together = (("ad", "addr", "port"),)


class RouterWeb(SCIONWebElement):
    NEIGHBOR_TYPES = (
        ('CHILD',) * 2,
        ('PARENT',) * 2,
        ('PEER',) * 2,
        ('CORE',) * 2,
    )

    neighbor_isd_id = models.IntegerField(null=True)
    neighbor_as_id = models.IntegerField(null=True)
    neighbor_type = models.CharField(max_length=10, choices=NEIGHBOR_TYPES)

    interface_id = models.IntegerField()
    interface_addr = models.GenericIPAddressField()
    interface_port = models.IntegerField()
    # Allow the toaddr and toport be null since the user might not yet
    # have the complete remote router information.
    interface_toaddr = models.GenericIPAddressField(null=True)
    interface_toport = models.IntegerField(null=True)

    def get_dict(self):
        out_dict = super(RouterWeb, self).get_dict()
        out_dict['Interface'] = {'NeighborType': self.neighbor_type,
                                 'NeighborISD': self.neighbor_isd_id,
                                 'NeighborAD': self.neighbor_as_id,
                                 'Addr': str(self.interface_addr),
                                 'AddrType': 'IPV4',
                                 'ToAddr': str(self.interface_toaddr),
                                 'UdpPort': self.interface_port,
                                 'ToUdpPort': self.interface_toport,
                                 'IFID': self.interface_id,
                                 }
        return out_dict

    class Meta:
        verbose_name = 'Router'
        unique_together = (("ad", "addr", "port"),)


class SibraServerWeb(SCIONWebElement):
    prefix = SIBRA_SERVICE

    class Meta:
        verbose_name = 'SIBRA server'
        unique_together = (("ad", "addr", "port"),)


class JoinRequest(models.Model):
    STATUS_OPTIONS = ['NONE', 'SENT', 'ACCEPTED', 'DECLINED']
    created_by = models.ForeignKey(User)

    isd_to_join = models.IntegerField(default=-1)
    join_as_a_core = models.BooleanField(default=False)
    status = models.CharField(max_length=20,
                              choices=zip(STATUS_OPTIONS, STATUS_OPTIONS),
                              default='NONE')

    sig_pub_key = models.CharField(max_length=100, null=True, blank=True)
    sig_priv_key = models.CharField(max_length=100, null=True, blank=True)
    enc_pub_key = models.CharField(max_length=100, null=True, blank=True)
    enc_priv_key = models.CharField(max_length=100, null=True, blank=True)

    certificate = models.CharField(max_length=1000, null=True, blank=True)
    trc = models.CharField(max_length=500, null=True, blank=True)

    def is_accepted(self):
        return self.status == 'ACCEPTED'


class ConnectionRequest(models.Model):
    STATUS_OPTIONS = ['NONE', 'SENT', 'APPROVED', 'DECLINED']
    LINK_TYPE = ['PARENT', 'CHILD', 'PEER', 'CORE']
    OVERLAY_TYPE = ['IPv4', 'IPv6', 'UDP/IPv4', 'UDP/IPv6']

    created_by = models.ForeignKey(User)
    connect_to = models.CharField(max_length=100, null=True, blank=True)
    connect_from = models.ForeignKey(AD, blank=True, null=True)
    info = models.TextField()
    router_public_ip = models.GenericIPAddressField()
    router_public_port = models.IntegerField(default=int(PORT))
    # router_info is the IP (and port) shown in the ConnectionRequest form
    # to select from.
    router_info = models.TextField(null=True)
    mtu = models.IntegerField(null=True, default=DEFAULT_MTU)
    bandwidth = models.IntegerField(null=True, default=DEFAULT_BANDWIDTH)
    link_type = models.CharField(max_length=20,
                                 choices=zip(LINK_TYPE, LINK_TYPE),
                                 default='PARENT')
    overlay_type = models.CharField(max_length=20,
                                    choices=zip(OVERLAY_TYPE, OVERLAY_TYPE),
                                    default='UDP/IPv4')
    status = models.CharField(max_length=20,
                              choices=zip(STATUS_OPTIONS, STATUS_OPTIONS),
                              default='NONE')

    related_fields = ('connect_from__isd', 'created_by')
    objects = SelectRelatedModelManager()

    def is_approved(self):
        return self.status == 'APPROVED'
