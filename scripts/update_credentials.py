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

"""
:mod:`update_credentials` --- Simple credential update tool.
============================================================

This is a simple utility tool to update credentials stored in
scion-web's database for a given ISD.

The tool will update the following entries in the given ISD:
- AS Certificate
- TRC
- Enc Signing Key
- Priv Signing Key
- Master AS Key

The tools assumes that the provided directory structure looks like a typical
gen folder that's generated via generator.py or scion-web.

Example usage:

python3 ./scripts/update_credentials.py --dir=<path_to_isd_folder> --isd=2

"""

# Stdlib
import argparse
import json
import os
import re
import sys
import yaml
from os.path import dirname as d

WEB_SCION_DIR = d(d(os.path.abspath(__file__)))  # noqa
sys.path.insert(0, WEB_SCION_DIR)  # noqa
# Set up the Django environment
os.environ['DJANGO_SETTINGS_MODULE'] = 'web_scion.settings.private'  # noqa


# External packages
import django

# SCION
from lib.crypto.asymcrypto import (
    get_core_sig_key_file_path,
    get_core_sig_key_raw_file_path,
    get_enc_key_file_path,
    get_sig_key_file_path,
    get_sig_key_raw_file_path,
)
from lib.crypto.certificate_chain import get_cert_chain_file_path
from lib.crypto.trc import get_trc_file_path
from lib.crypto.util import (
    get_ca_cert_file_path,
    get_ca_private_key_file_path,
    get_offline_key_file_path,
    get_offline_key_raw_file_path,
    get_online_key_file_path,
    get_online_key_raw_file_path,
)
from lib.defines import (
    AS_CONF_FILE,
    GEN_PATH,
    PROJECT_ROOT,
    TOPO_FILE,
)
from lib.packet.scion_addr import ISD_AS
from lib.topology import Topology
from lib.util import read_file
from topology.generator import INITIAL_CERT_VERSION, INITIAL_TRC_VERSION

# SCION-WEB
from ad_manager.models import AD

# SCION-Utilities
from sub.util.local_config_util import ASCredential

django.setup()  # noqa
AS_PREFIX = 'AS'


def _json_file_to_str(file_path):
    """
    Utility function to read in a JSON file and return as a string.
    :param file_path: Location of the file.
    :type file_path: string
    :returns: JSON object represented as a string.
    :rtype: string
    """
    with open(file_path) as json_file:
        json_data = json.load(json_file)
        res = json.dumps(json_data, indent=4, sort_keys=True, separators=(',', ': '))
        return res


def _yaml_file_to_dict(file_path):
    """
    Utility function to read in a YAML file and return as a dictionary.
    :param file_path: Location of the file.
    :type file_path: string
    :returns: Contents of the YAML file as a dictionary.
    :rtype: dict
    """
    with open(file_path, 'r') as stream:
        try:
            return yaml.load(stream)
        except yaml.YAMLError as e:
            print("Error loading YAML file: %s" % e)
            return None


def _update_credentials(path):
    """
    Main routine to update with relevant ISD with new credentials.
    :param path: Location of the ISD folder, containing new credentials.
    :type path: string
    :param isd_id: ISD the AS belongs to.
    :type isd_id: string
    """
    for (dirpath, dirnames, filenames) in os.walk(path):
        for dirname in dirnames:
            if dirname.startswith('AS'):
                token = dirpath.split('/')
                isd_id = token[len(token) - 1][3:]
                as_id = re.search('AS(.*)', dirname).group(1)
                isd_as = ISD_AS.from_values(isd_id, as_id)
                cred_obj = _load_credentials(os.path.join(dirpath, dirname), isd_as)
                _create_update_as(cred_obj, isd_as)


def _load_credentials(as_path, isd_as):
    print("Updating AS%s" % isd_as)
    # The element to get the credentials from.
    # We assume that the beacon server exists in every AS configuration.
    key_dict = {}
    core_key_dict = {}
    as_path = os.path.join(PROJECT_ROOT, GEN_PATH, 'ISD%s/AS%s' % (isd_as[0], isd_as[1]))
    instance_id = "bs%s-%s-1" % (isd_as[0], isd_as[1])
    instance_path = os.path.join(as_path, instance_id)
    topo_path = os.path.join(instance_path, TOPO_FILE)

    # Credential files for all ASes
    as_key_path = {
        'cert_path': get_cert_chain_file_path(instance_path, isd_as, INITIAL_CERT_VERSION),
        'trc_path': get_trc_file_path(instance_path, isd_as[0], INITIAL_TRC_VERSION),
        'enc_key_path': get_enc_key_file_path(instance_path),
        'sig_key_path': get_sig_key_file_path(instance_path),
        'sig_key_raw_path': get_sig_key_raw_file_path(instance_path),
        'as_config_path': os.path.join(instance_path, AS_CONF_FILE),
    }

    # Credential files for core ASes
    core_key_path = {
        'core_sig_key_path': get_core_sig_key_file_path(instance_path),
        'core_sig_key_raw_path': get_core_sig_key_raw_file_path(instance_path),
        'online_key_path': get_online_key_file_path(instance_path),
        'online_key_raw_path': get_online_key_raw_file_path(instance_path),
        'offline_key_path': get_offline_key_file_path(instance_path),
        'offline_key_raw_path': get_offline_key_raw_file_path(instance_path),
    }

    for key, path in as_key_path.items():
        try:
            if key.startswith('cert'):
                cert = _json_file_to_str(path)
            elif key.startswith('trc'):
                trc = _json_file_to_str(path)
            elif key.startswith('as'):
                as_config_dict = _yaml_file_to_dict(path)
                key_dict['master_as_key'] = as_config_dict['MasterASKey']
            else:
                key_name = key[:len(key)-5]
                key_dict[key_name] = read_file(path)[:-1]
        except IOError as err:
            print("IOError({0}): {1}" % (err, path))
            exit(1)
    tp = Topology.from_file(topo_path)
    if tp.is_core_as:
        for key, path in core_key_path.items():
            try:
                key_name = key[:len(key)-5]
                core_key_dict[key_name] = read_file(path)[:-1]
            except IOError as err:
                print("IOError({0}): {1}" % (err, path))
                exit(1)

    return ASCredential(cert, trc, key_dict, core_key_dict)


def _create_update_as(credentials, isd_as):
    """
    Copy the new credentials and place into relevant DB tables of
    scion-web. If the AS is not already existing, it will create a new
    entry in AD table.
    :param as_path: Directory containing the new AS credentials
    :type as_path: string
    :param isd_id: ISD the AS belongs to.
    :type isd_id: string
    :param as_id: AS ID.
    :type as_id: string
    """
    print("Calling update or create for AS%s" % isd_as)
    try:
        as_obj = AD.objects.get(as_id=isd_as[1], isd_id=isd_as[0])
    except AD.DoesNotExist:
        print(isd_as, " does not exist, creating it..")
        as_obj = AD.objects.create(as_id=isd_as[1], isd_id=isd_as[0], original_topology={})

    print("Setting credentials for AS%s" % isd_as)
    as_obj.certificate = credentials.certificate
    as_obj.trc = credentials.trc
    as_obj.keys = credentials.keys
    as_obj.core_keys = credentials.core_keys
    as_obj.save()


def main():
    """
    Parse the command-line arguments and invoke the credential update routine.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir",
                        help='Credentials directory of the ISD',
                        default=os.path.join(PROJECT_ROOT, GEN_PATH))
    parser.add_argument("--isd",
                        help='ISD ID')
    args = parser.parse_args()
    if not args.isd:
        dir_path = os.path.abspath(os.path.expanduser(args.dir))
    else:
        dir_path = os.path.abspath(os.path.expanduser(os.path.join(args.dir, 'ISD%s' % args.isd)))
    if not os.path.exists(dir_path):
        print("Directory does not exist. Exiting..")
        exit()
    _update_credentials(dir_path)


if __name__ == '__main__':
    main()
