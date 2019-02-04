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
import json

# External packages
import jsonfield
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.db import models, IntegrityError

# SCION
from lib.types import ServiceType
from lib.defines import DEFAULT_MTU
from lib.packet.scion_addr import ISD_AS

# SCION-WEB
from ad_manager.util.common import empty_dict
from ad_manager.util.defines import (
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


def transform_integer_ids_in_topology(topo):
    """
    Transform the topology so that keys that are string representations
    of integers are replaced with their integers. E.g. "1" replaced with 1
    These transformations are needed by the generating code of scionproto
    because it expects some keys to be integers and not strings
    """
    assert isinstance(topo, dict), 'Topology should be a dictionary'
    jsontopo = json.dumps(topo)
    def jsonhook(d):
        ret = {}
        for k,v in d.items():
            try:
                k = int(k)
            except:
                pass
            ret[k] = v
        return ret
    topo = json.loads(jsontopo, object_hook=jsonhook)
    return topo

class AD(models.Model):
    as_id = models.IntegerField(default=-1)
    isd = models.ForeignKey('ISD')
    as_id_str = models.CharField(max_length=15, null=True)
    is_core_ad = models.BooleanField(default=False)
    simple_conf_mode = models.BooleanField(default=False)
    is_open = models.BooleanField(default=True)
    commit_hash = models.CharField(max_length=100, default='')
    md_host = models.GenericIPAddressField(default='127.0.0.1')
    original_topology = jsonfield.JSONField(default=empty_dict)
    sig_pub_key = models.CharField(max_length=100, null=True, blank=True)
    sig_priv_key = models.CharField(max_length=100, null=True, blank=True)
    enc_pub_key = models.CharField(max_length=100, null=True, blank=True)
    enc_priv_key = models.CharField(max_length=100, null=True, blank=True)
    master_as_key = models.CharField(max_length=100, null=True, blank=True)
    certificate = models.TextField(null=True, blank=True)
    trc = models.TextField(null=True, blank=True)
    keys = jsonfield.JSONField(default=empty_dict)
    core_keys = jsonfield.JSONField(default=empty_dict)

    # Use custom model manager with select_related()
    objects = SelectRelatedModelManager()

    @classmethod
    def from_db(cls, db, field_names, values):
        """Create an AD instance from the DB. Just transform the topology"""
        ad = super().from_db(db, field_names, values)
        ad.original_topology = transform_integer_ids_in_topology(ad.original_topology)
        return ad

    class Meta:
        unique_together = (("as_id", "isd"),)
        verbose_name = 'AD'
        ordering = ['as_id_str']

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
            'CertificateService': {},
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
            router_addr = router['InternalAddrs']['IPv4']
            addr_info = router_addr['PublicOverlay']
            internal_public_obj, _ = BorderRouterAddress.objects.update_or_create(
                addr=addr_info['Addr'],
                l4port=addr_info['OverlayPort'],
                addr_type='IPv4',
                is_public=True,
                router=br_obj,
                ad=self
            )
            addr_info = router_addr.get('BindOverlay', None)
            if addr_info:
                internal_bound_obj, _ = BorderRouterAddress.objects.update_or_create(
                addr=addr_info['Addr'],
                l4port=addr_info['OverlayPort'],
                addr_type='IPv4',
                is_public=False,
                router=br_obj,
                ad=self
            )
            else:
                internal_bound_obj = None
            # TODO: we need to update the model: BorderRouterAddress should have also CtrlAddr, both should
            # have public + bind address. BorderRouterInterface should not have an index
            # But I don't find where we read this data for anything !

            for if_id, intf in router["Interfaces"].items():
                isd_as = ISD_AS(intf["ISD_AS"])
                br_addr_obj = internal_public_obj
                br_inft_obj, _ = BorderRouterInterface.objects.update_or_create(
                    addr=intf['PublicOverlay']['Addr'],
                    l4port=intf['PublicOverlay']['OverlayPort'],
                    remote_addr=intf['RemoteOverlay']['Addr'],
                    remote_l4port=intf['RemoteOverlay']['OverlayPort'],
                    internal_addr_idx=0,
                    interface_id=if_id,
                    bandwidth=intf['Bandwidth'],
                    mtu=intf['MTU'],
                    neighbor_isd_id=isd_as[0],
                    neighbor_as_id=isd_as[1],
                    neighbor_as_id_str=isd_as.as_str(),
                    neighbor_type=intf["LinkTo"],
                    router_addr=br_addr_obj,
                    ad=self,
                    bind_addr=intf['BindOverlay']['Addr'] if 'BindOverlay' in intf.keys() else None,
                    bind_l4port=intf['BindOverlay']['OverlayPort'] if 'BindOverlay' in intf.keys() else None,
                )

    def fill_service_info(self, service_dict):
        """
        Update the service information in the database.
        (i.e., Service and ServiceAddress tables.)
        :param dict service_dict: (e.g., topo_dict['BeaconService'])
        """
        for name, service in service_dict.items():
            srv_obj, _ = Service.objects.update_or_create(name=name, ad=self)
            service_addrs = service['Addrs']['IPv4']
            addr_info = service_addrs['Public']
            srv_public_obj, _ = ServiceAddress.objects.update_or_create(
                addr=addr_info['Addr'],
                l4port=addr_info['L4Port'],
                addr_type='IPv4',
                is_public=True,
                service=srv_obj,
                ad=self
            )
            addr_info = service_addrs.get('Bind', None)
            if addr_info:
                srv_bind_obj, _ = ServiceAddress.objects.update_or_create(
                    addr=addr_info['Addr'],
                    l4port=addr_info['L4Port'],
                    addr_type='IPv4',
                    is_public=False,
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

        try:
            self.fill_router_info(routers)
            self.fill_service_info(beacon_servers)
            self.fill_service_info(certificate_servers)
            self.fill_service_info(path_servers)

        except IntegrityError:
            logging.warning("Integrity error in AD.fill_from_topology(): "
                            "ignoring")
            raise

    def fill_cloud_info(self, topology_params):
        """
        Update cloud machine information in the database
        :param QueryDict topology_params
        """
        self.commit_hash = topology_params['commitHash']
        self.save()
        unique_addr = topology_params.getlist('inputCloudAddress')
        providers = topology_params.getlist('inputCloudEngine')
        host_name = topology_params.getlist('inputHostname')
        for i in range(len(unique_addr)):
            cloud_obj, _ = CloudMachine.objects.update_or_create(
                addr=unique_addr[i],
                host_name=host_name[i],
                cloud_provider=providers[i],
                ad=self
            )

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
    neighbor_as_id_str = models.CharField(max_length=15, null=True)
    neighbor_type = models.CharField(max_length=10, choices=NEIGHBOR_TYPES)
    router_addr = models.ForeignKey(BorderRouterAddress)
    ad = models.ForeignKey(AD)


class CloudMachine(models.Model):
    addr = models.GenericIPAddressField()
    host_name = models.CharField(max_length=20, null=True)
    cloud_provider = models.CharField(max_length=20, null=True)
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
    prefix = ServiceType.BS

    class Meta:
        verbose_name = 'Beacon server'
        unique_together = (("ad", "addr", "port"),)


class CertificateServerWeb(SCIONWebElement):
    prefix = ServiceType.CS

    class Meta:
        verbose_name = 'Certificate server'
        unique_together = (("ad", "addr", "port"),)


class PathServerWeb(SCIONWebElement):
    prefix = ServiceType.PS

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

# Sibra service is no longer available until a new sibra service is delivered
"""
class SibraServerWeb(SCIONWebElement):
    prefix = SIBRA_SERVICE

    class Meta:
        verbose_name = 'SIBRA server'
        unique_together = (("ad", "addr", "port"),)
"""

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
