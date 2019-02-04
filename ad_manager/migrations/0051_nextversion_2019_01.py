# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models

import os
import base64


def transform_topology(topo):
    # transform the dictionary to support nextversion
    for name, srv in topo.items():
        if not isinstance(srv, dict):
            continue
        if isinstance(srv, dict) and len(srv) > 0:
            if name == 'PathService' or name == 'BeaconService' or name == 'CertificateService':
                for k, v in list(srv.items()):
                    if not isinstance(v, dict) or len(v) < 1:
                        continue
                    addrs = {}
                    for addr_type, addr_list in v.items():
                        if not isinstance(addr_list, list) or not isinstance(addr_list[0], dict):
                            raise Exception('Should have found a dictionary as a value of the array of addresses.')
                        addrs[addr_type] = addr_list[0]
                    srv[k] = {'Addrs': {'IPv4': addrs}}
            elif name == 'BorderRouters':
                for brname, br in list(srv.items()):
                    if not isinstance(br, dict) or len(br) != 2 or 'Interfaces' not in br.keys() or \
                    'InternalAddrs' not in br.keys():
                        continue
                    addr = br['InternalAddrs'][0]['Public'][0]
                    InternalAddrs = {'IPv4':{'PublicOverlay':{'Addr': addr['Addr'], 'OverlayPort': addr['L4Port']}}}
                    # TODO check that using InternalAddr - 1000 is not clashing with anything
                    CtrlAddr = {'IPv4':{'Public':{'Addr': addr['Addr'], 'L4Port':addr['L4Port']-1000}}}
                    # Bind addresses needed?
                    if 'Bind' in br['InternalAddrs'][0]:
                        addr = br['InternalAddrs'][0]['Bind'][0]
                        InternalAddrs['IPv4']['BindOverlay'] = {'Addr': addr['Addr'], 'OverlayPort': addr['L4Port']}
                        CtrlAddr['IPv4']['Bind'] = {'Addr': addr['Addr'], 'L4Port': addr['L4Port']-1000}
                    Interfaces = {}
                    for ifnum,iface in br['Interfaces'].items():
                        newiface = {'ISD_AS': iface['ISD_AS'],
                            'LinkTo': iface['LinkTo'],
                            'Overlay': iface['Overlay'],
                            'Bandwidth': iface['Bandwidth'],
                            'MTU': iface['MTU'],
                            'PublicOverlay':{'Addr': iface['Public']['Addr'], 'OverlayPort': iface['Public']['L4Port']},
                            'RemoteOverlay':{'Addr': iface['Remote']['Addr'], 'OverlayPort': iface['Remote']['L4Port']},
                        }
                        if 'Bind' in iface:
                            newiface['BindOverlay'] = {'Addr': iface['Bind']['Addr'], 'OverlayPort': iface['Bind']['L4Port']}
                        Interfaces[ifnum] = newiface
                    srv[brname] = { 'CtrlAddr': CtrlAddr,
                        'InternalAddrs': InternalAddrs,
                        'Interfaces': Interfaces,
                    }
    return topo

def transform_keys(keys):
    # it has one missing key, a renamed one, and also a superfluous one. Fix it:
    keys['master0_as_key'] = keys['master_as_key']
    keys['master1_as_key'] = base64.b64encode(os.urandom(16)).decode('utf-8')
    del keys['master_as_key']
    del keys['sig_key_raw']



def forward(apps, schema_editor):
    model = apps.get_model('ad_manager', 'AD')
    for ad in model.objects.all():
        transform_keys(ad.keys)
        transform_topology(ad.original_topology)
        ad.save()

def reverse(apps, schema_editor):
    print('\nReverse transformation implemented as NOOP. Please change this if necessary.')

class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0050_auto_20180626_1504'),
    ]

    operations = [
        migrations.RunPython(forward, reverse)
    ]
