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
SCION_ROOT_DIR = d(d(WEB_SCION_DIR))  # noqa
SCION_PYTHON_ROOT_DIR = os.path.join(SCION_ROOT_DIR, 'python')  # noqa
sys.path.insert(0, WEB_SCION_DIR)  # noqa
sys.path.insert(0, SCION_ROOT_DIR)  # noqa
sys.path.insert(0, SCION_PYTHON_ROOT_DIR)  # noqa

# Set up the Django environment
os.environ['DJANGO_SETTINGS_MODULE'] = 'web_scion.settings.private'  # noqa

# External packages
import django

# SCION
from lib.crypto.util import (
    CERT_DIR,
    KEYS_DIR,
)
from lib.defines import AS_CONF_FILE
from lib.util import read_file

# SCION-WEB
from ad_manager.models import AD

django.setup()  # noqa

AS_PREFIX = 'AS'
SIG_PRIV_KEY = 'as-sig.seed'
SIG_PRIV_KEY_OLD = 'as-sig.key'
ENC_PRIV_KEY = 'as-decrypt.key'


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


def _update_credentials(path, isd_id):
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
                as_id = re.search('AS(.*)', dirname).group(1)
                _create_update_as(os.path.join(dirpath, dirname), isd_id, as_id)


def _create_update_as(as_path, isd_id, as_id):
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
    print("Updating AS %s, %s" % (isd_id, as_id))
    # The element to get the credentials from.
    # We assume that the beacon server exists in every AS configuration.
    elem_id = "bs%s-%s-1" % (isd_id, as_id)
    # TODO(ercanucan): use the built-in defines
    cert_file = "ISD%s-AS%s-V0.crt" % (isd_id, as_id)
    trc_file = "ISD%s-V0.trc" % isd_id

    cert_path = os.path.join(as_path, elem_id, CERT_DIR, cert_file)
    trc_path = os.path.join(as_path, elem_id, CERT_DIR, trc_file)
    if os.path.exists(os.path.join(as_path, elem_id, KEYS_DIR, SIG_PRIV_KEY)):
        sig_priv_key_path = os.path.join(as_path, elem_id, KEYS_DIR, SIG_PRIV_KEY)
    else:
        sig_priv_key_path = os.path.join(as_path, elem_id, KEYS_DIR, SIG_PRIV_KEY_OLD)
    enc_priv_key_path = os.path.join(as_path, elem_id, KEYS_DIR, ENC_PRIV_KEY)
    as_config_path = os.path.join(as_path, elem_id, AS_CONF_FILE)

    cert = _json_file_to_str(cert_path)
    trc = _json_file_to_str(trc_path)
    sig_priv_key = read_file(sig_priv_key_path)
    enc_priv_key = read_file(enc_priv_key_path)
    as_config_dict = _yaml_file_to_dict(as_config_path)
    master_as_key = as_config_dict['MasterASKey']

    print("Calling update or create for AS %s, %s" % (isd_id, as_id))
    try:
        as_obj = AD.objects.get(as_id=as_id, isd_id=isd_id)
    except AD.DoesNotExist:
        print(as_id, " does not exist, creating it..")
        as_obj = AD.objects.create(as_id=as_id, isd_id=isd_id, original_topology={})

    print("Setting credentials for AS %s, %s" % (isd_id, as_id))
    as_obj.certificate = cert
    as_obj.trc = trc
    as_obj.sig_priv_key = sig_priv_key
    as_obj.enc_priv_key = enc_priv_key
    as_obj.master_as_key = master_as_key
    as_obj.save()


def main():
    """
    Parse the command-line arguments and invoke the credential update routine.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir",
                        help='Credentials directory of the ISD')
    parser.add_argument("--isd",
                        help='ISD ID')
    args = parser.parse_args()
    dir_path = os.path.abspath(os.path.expanduser(args.dir))
    if not os.path.exists(dir_path):
        print("Directory does not exist. Exiting..")
        exit()
    _update_credentials(dir_path, args.isd)


if __name__ == '__main__':
    main()
