#!/usr/bin/env python3

"""
Import ISD/AD data from topology files
"""

# Stdlib
import glob
import os
import sys
from os.path import dirname as d

sys.path.insert(0, d(d(d(os.path.abspath(__file__)))))  # noqa

# External packages
import django
from django.db import transaction

import yaml

# SCION
from ad_management.common import WEB_SCION_DIR
from lib.defines import GEN_PATH, PROJECT_ROOT
from lib.topology import Topology

# Set up the Django environment
os.environ['DJANGO_SETTINGS_MODULE'] = 'web_scion.settings.private'  # noqa # £££
sys.path.insert(0, WEB_SCION_DIR)  # noqa
django.setup()  # noqa

GEN_PATH = os.path.join(PROJECT_ROOT, GEN_PATH)

# Django app imports
from ad_manager.models import AD, ISD
from django.contrib.auth.models import User


def clear_everything():
    print('> Deleting everything...')
    ISD.objects.all().delete()


def add_users():
    """
    Create a superuser ('admin') and an ordinary user ('user1')
    """
    try:
        User.objects.get(username='admin').delete()
    except User.DoesNotExist:
        pass
    User.objects.create_superuser(username='admin', password='admin', email='')
    print('> Superuser was created')

    try:
        User.objects.get(username='user1').delete()
    except User.DoesNotExist:
        pass
    User.objects.create_user(username='user1', password='user1', email='')
    print('> User (user1) was created')


def get_topology(file):
    """
    Reads in the topology file and serves the relevant part of that
    to the visualization extension.
    :returns: A list of links extracted from the topology file.
    :rtype: list
    """
    with open(file, 'r') as stream:
        try:
            topo_dict = yaml.load(stream)
            return topo_dict
        except (yaml.YAMLError, KeyError) as e:
            return []

def reload_data():

    transaction.set_autocommit(False)
    clear_everything()
    add_users()

    # Add model instances
    yaml_path = os.path.join(GEN_PATH, 'ISD*', 'AS*', 'endhost', 'topology.yml')
    topology_files = glob.glob(yaml_path)
    ad_num = len(topology_files)
    print("> {} yaml topology files found".format(ad_num))

    isds = {}
    as_topos = []
    as_topo_dicts = {}

    same_as_ids = False
    # Iterate over all topology files and fill some data structures
    for topo_file in topology_files:
        topo_dict = get_topology(topo_file)
        topology = Topology.from_dict(topo_dict)
        isds[topology.isd_as[0]] = None

        if not same_as_ids and topology.isd_as._as in as_topo_dicts:
            same_as_ids = True
        as_topo_dicts[topology.isd_as._as] = topo_dict
        as_topos.append(topology)

        as_topos = sorted(as_topos, key=lambda t: t.isd_as._as)
    assert len(as_topos) == ad_num

    if same_as_ids:
        id_map = {}
        print("> Several ADs with identical IDs are found. Currently, this "
              "case is not supported. Renumerating ADs...")
        ad_id = 1
        for topo in as_topos:
            id_map[(topo.ad_id, topo.isd_id)] = ad_id
            topo.ad_id = ad_id
            ad_id += 1

        # Fixing routers
        for topo in as_topos:
            routers = topo.get_all_edge_routers()
            for router in routers:
                neighbor_id = router.interface.neighbor_ad
                new_neighbor_id = id_map[(neighbor_id,
                                          router.interface.neighbor_isd)]
                router.interface.neighbor_ad = new_neighbor_id

    # Create ISD objects
    for isd_id in sorted(isds.keys()):  # sorted(isds.keys()):  #  TODO: Does it need sorting?
        isd = ISD(id=isd_id)
        isd.save()
        isds[isd_id] = isd

    # First, save all add ADs to avoid IntegrityError
    report_ranges = {int(ad_num / 10.0 * x): x * 10 for x in range(1, 11)}
    for i, as_topo in enumerate(as_topos, start=1):
        if i in report_ranges:
            print("{}%".format(report_ranges[i]))
        AD.objects.create(id=as_topo.isd_as._as, isd=isds[as_topo.isd_as._isd],  # TODO: avoid accessing protected class members
                          is_core_ad=as_topo.is_core_as,
                          dns_domain=as_topo.dns_domain)
    transaction.commit()
    print("> ADs instances were added")

    # Second, add routers, servers, etc.
    for as_topo in as_topos:
        ad = AD.objects.get(id=as_topo.isd_as._as, isd=isds[as_topo.isd_as._isd])
        topo_dict = as_topo_dicts[ad.id]
        ad.fill_from_topology(topo_dict)
        print('> AD {} is loaded'.format(ad))
    transaction.commit()
    transaction.set_autocommit(True)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == 'users':
        add_users()
    else:
        reload_data()
