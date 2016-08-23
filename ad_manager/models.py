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
from ad_manager.util.common import empty_dict
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    PATH_SERVICE,
    SIBRA_SERVICE
)

PORT = 50000
PACKAGE_DIR_PATH = 'gen'


class OrganisationAdmin(models.Model):
    user = models.OneToOneField(User)
    is_org_admin = models.BooleanField(default=False)
    key = models.CharField(max_length=260, null=False, blank=True)
    secret = models.CharField(max_length=260, null=False, blank=True)


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
    id = models.AutoField(primary_key=True)
    isd = models.ForeignKey('ISD')
    is_core_ad = models.BooleanField(default=False)
    is_open = models.BooleanField(default=True)
    md_host = models.GenericIPAddressField(default='127.0.0.1')
    original_topology = jsonfield.JSONField(default=empty_dict)
    sig_pub_key = models.CharField(max_length=100, null=True, blank=True)
    sig_priv_key = models.CharField(max_length=100, null=True, blank=True)
    enc_pub_key = models.CharField(max_length=100, null=True, blank=True)
    enc_priv_key = models.CharField(max_length=100, null=True, blank=True)
    certificate = models.CharField(max_length=500, null=True, blank=True)

    # Use custom model manager with select_related()
    objects = SelectRelatedModelManager()

    def generate_topology_dict(self):
        """
        Create a Python dictionary with the stored AS topology.
        """
        assert isinstance(self.original_topology, dict)
        out_dict = copy.deepcopy(self.original_topology)
        out_dict.update({
            'ISDID': int(self.isd_id), 'ADID': int(self.id),
            'Core': int(self.is_core_ad),
            'BorderRouters': {}, 'PathServers': {}, 'BeaconServers': {},
            'CertificateServers': {}, 'SibraServers': {},
        })
        for router in self.routerweb_set.all():
            out_dict['BorderRouters'][str(router.name)] = router.get_dict()
        for ps in self.pathserverweb_set.all():
            out_dict['PathServers'][str(ps.name)] = ps.get_dict()
        for bs in self.beaconserverweb_set.all():
            out_dict['BeaconServers'][str(bs.name)] = bs.get_dict()
        for cs in self.certificateserverweb_set.all():
            out_dict['CertificateServers'][str(cs.name)] = cs.get_dict()
        for sb in self.sibraserverweb_set.all():
            out_dict['SibraServers'][str(sb.name)] = sb.get_dict()
        return out_dict

    def get_all_elements(self):
        elements = [self.routerweb_set.all(),
                    self.pathserverweb_set.all(),
                    self.beaconserverweb_set.all(),
                    self.certificateserverweb_set.all(),
                    self.sibraserverweb_set.all()]
        for element_group in elements:
            for element in element_group:
                yield element

    def get_all_element_ids(self):
        all_elements = self.get_all_elements()
        element_ids = [element.id_str() for element in all_elements]
        return element_ids

    def fill_from_topology(self, topology_dict, clear=False, auto_refs=False):
        """
        Add infrastructure elements (servers, routers) to the AD, extracted
        from the topology dictionary.
        """
        assert isinstance(topology_dict, dict), 'Dictionary expected'

        if clear:
            self.routerweb_set.all().delete()
            self.pathserverweb_set.all().delete()
            self.certificateserverweb_set.all().delete()
            self.beaconserverweb_set.all().delete()
            self.sibraserverweb_set.all().delete()

        self.original_topology = topology_dict
        self.is_core_ad = (topology_dict['Core'] == 1)
        self.save()

        routers = topology_dict["BorderRouters"]
        beacon_servers = topology_dict["BeaconServers"]
        certificate_servers = topology_dict["CertificateServers"]
        path_servers = topology_dict["PathServers"]
        sibra_servers = topology_dict["SibraServers"]

        try:
            for name, router in routers.items():
                interface = router["Interface"]

                isd_as_split = interface["ISD_AS"].split('-')
                isd_str = isd_as_split[0]
                as_str = isd_as_split[1]

                try:
                    neighbor_ad = AD.objects.get(id=as_str,
                                                 isd=isd_str)
                except AD.DoesNotExist:
                    if auto_refs:
                        # Handles missing references
                        # breaks circular dependencies by creating empty ASes
                        # as needed
                        try:
                            isd = ISD.objects.get(id=isd_str)
                        except ISD.DoesNotExist:
                            isd = ISD(id=isd_str)
                            isd.save()
                        as_obj = AD.objects.create(id=as_str, isd=isd,
                                                   is_core_ad=0,
                                                   is_open=False)
                        as_obj.save()

                        neighbor_ad = AD.objects.get(id=as_str,
                                                     isd=isd_str)
                    else:
                        raise

                RouterWeb.objects.update_or_create(
                    addr=router["Addr"], ad=self,
                    addr_internal='',
                    port_internal=None,
                    name=name, neighbor_ad=neighbor_ad,
                    neighbor_type=interface["LinkType"],
                    interface_addr=interface["Addr"],
                    interface_toaddr=interface["ToAddr"],
                    interface_id=interface["IFID"],
                    interface_port=interface["UdpPort"],
                    interface_toport=interface["ToUdpPort"],
                )

            for name, bs in beacon_servers.items():
                BeaconServerWeb.objects.\
                    update_or_create(addr=bs["Addr"],
                                     addr_internal=bs["AddrInternal"],
                                     port_internal=bs["PortInternal"],
                                     name=name,
                                     ad=self)

            for name, cs in certificate_servers.items():
                CertificateServerWeb.objects.\
                    update_or_create(addr=cs["Addr"],
                                     addr_internal=cs["AddrInternal"],
                                     port_internal=cs["PortInternal"],
                                     name=name,
                                     ad=self)

            for name, ps in path_servers.items():
                PathServerWeb.objects.\
                    update_or_create(addr=ps["Addr"],
                                     addr_internal=ps["AddrInternal"],
                                     port_internal=ps["PortInternal"],
                                     name=name,
                                     ad=self)

            for name, sb in sibra_servers.items():
                SibraServerWeb.objects.\
                    update_or_create(addr=sb["Addr"],
                                     addr_internal=sb["AddrInternal"],
                                     port_internal=sb["PortInternal"],
                                     name=name,
                                     ad=self)
        except IntegrityError:
            logging.warning("Integrity error in AD.fill_from_topology(): "
                            "ignoring")
            raise

    def get_absolute_url(self):
        return reverse('ad_detail', args=[self.id])

    def get_full_process_name(self, id_str):
        if ':' in id_str:
            return id_str
        else:
            # changed for rpc log retrieval, to match new supervisord names
            return "as{}-{}:{}".format(self.isd.id, self.id, id_str)

    def __str__(self):
        return '{}-{}'.format(self.isd.id, self.id)

    class Meta:
        verbose_name = 'AD'
        ordering = ['id']


class SCIONWebElement(models.Model):
    addr = models.GenericIPAddressField()
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
        unique_together = (("ad", "addr"),)


class CertificateServerWeb(SCIONWebElement):
    prefix = CERTIFICATE_SERVICE

    class Meta:
        verbose_name = 'Certificate server'
        unique_together = (("ad", "addr"),)


class PathServerWeb(SCIONWebElement):
    prefix = PATH_SERVICE

    class Meta:
        verbose_name = 'Path server'
        unique_together = (("ad", "addr"),)


class RouterWeb(SCIONWebElement):
    NEIGHBOR_TYPES = (
        ('CHILD',) * 2,
        ('PARENT',) * 2,
        ('PEER',) * 2,
        ('ROUTING',) * 2,
    )

    neighbor_ad = models.ForeignKey(AD, related_name='neighbors')
    neighbor_type = models.CharField(max_length=10, choices=NEIGHBOR_TYPES)

    interface_id = models.IntegerField()
    interface_addr = models.GenericIPAddressField()
    interface_toaddr = models.GenericIPAddressField()
    interface_port = models.IntegerField(default=int(PORT))
    interface_toport = models.IntegerField(default=int(PORT))

    def id_str(self):
        return "er{}-{}er{}-{}".format(self.ad.isd_id, self.ad_id,
                                       self.neighbor_ad.isd_id,
                                       self.neighbor_ad.id)

    def get_dict(self):
        out_dict = super(RouterWeb, self).get_dict()
        out_dict['Interface'] = {'NeighborType': self.neighbor_type,
                                 'NeighborISD': int(self.neighbor_ad.isd_id),
                                 'NeighborAD': int(self.neighbor_ad.id),
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
        unique_together = (("ad", "addr"),)


class SibraServerWeb(SCIONWebElement):
    prefix = SIBRA_SERVICE

    class Meta:
        verbose_name = 'SIBRA server'
        unique_together = (("ad", "addr"),)


class ConnectionRequest(models.Model):
    STATUS_OPTIONS = ['NONE', 'SENT', 'APPROVED', 'DECLINED']

    created_by = models.ForeignKey(User)
    connect_to = models.ForeignKey(AD, related_name='received_requests')
    new_ad = models.ForeignKey(AD, blank=True, null=True)
    info = models.TextField()
    router_public_ip = models.GenericIPAddressField()
    router_public_port = models.IntegerField(default=int(PORT))
    status = models.CharField(max_length=20,
                              choices=zip(STATUS_OPTIONS, STATUS_OPTIONS),
                              default='NONE')
    # TODO(rev112) change to FilePathField?
    package_path = models.CharField(max_length=1000, blank=True, null=True)

    related_fields = ('new_ad__isd', 'connect_to__isd', 'created_by')
    objects = SelectRelatedModelManager()

    def is_approved(self):
        return self.status == 'APPROVED'
