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
"""
:mod:`local_config_generator` --- Local config generator tool for SCION-WEB
===========================================================================

"""
# Stdlib
from collections import defaultdict
import logging
import os
import yaml
from shutil import rmtree


# SCION
from lib.defines import (
    PROJECT_ROOT,
    PROM_FILE,
)
from lib.packet.scion_addr import ISD_AS
from lib.util import write_file
from topology.common import TopoID
from topology.prometheus import PrometheusGenerator

# SCION-WEB
from ad_manager.models import AD
from ad_manager.util.defines import PROM_PORT_OFFSET
from ad_manager.util.simple_config.simple_config import check_simple_conf_mode

# SCION-Utilities
from sub.util.local_config_util import (
    generate_sciond_config,
    get_elem_dir,
    prep_supervisord_conf,
    write_as_conf_and_path_policy,
    write_certs_trc_keys,
    write_dispatcher_config,
    write_overlay_config,
    write_toml_files,
    write_supervisord_config,
    write_topology_file,
    write_zlog_file,
    generate_prom_config,
    TYPES_TO_EXECUTABLES,
    TYPES_TO_KEYS,
)

WEB_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logger = logging.getLogger("scion-web")


def create_local_gen(isdas, tp):
    """
    Creates the usual gen folder structure for an ISD/AS under web_scion/gen,
    ready for Ansible deployment
    :param str isdas: ISD-AS as a string
    :param dict tp: the topology parameter file as a dict of dicts
    """
    assert isinstance(isdas, TopoID), type(isdas)
    as_obj = _get_as_obj(isdas)
    check_simple_conf_mode(tp, isdas[0], isdas[1])
    local_gen_path = os.path.join(WEB_ROOT, 'gen')
    write_dispatcher_config(local_gen_path)
    as_path = 'ISD%s/AS%s/' % (isdas[0], isdas.as_file_fmt())
    as_path = get_elem_dir(local_gen_path, isdas, "")
    rmtree(as_path, True)
    write_toml_files(tp, isdas)
    for service_type, type_key in TYPES_TO_KEYS.items():
        executable_name = TYPES_TO_EXECUTABLES[service_type]
        instances = tp[type_key].keys()
        for instance_name in instances:
            config = prep_supervisord_conf(tp[type_key][instance_name], executable_name,
                                           service_type, instance_name, isdas)
            instance_path = get_elem_dir(local_gen_path, isdas, instance_name)
            write_certs_trc_keys(isdas, as_obj, instance_path)
            write_as_conf_and_path_policy(isdas, as_obj, instance_path)
            write_supervisord_config(config, instance_path)
            write_topology_file(tp, type_key, instance_path)
            write_zlog_file(service_type, instance_name, instance_path)
    generate_sciond_config(isdas, as_obj, tp)
    write_overlay_config(local_gen_path)
    # TODO : confirm that the gen/prometheus.yml and gen/ISDXX/ASffaa_0_XXXX/prometheus.yml are not necessary
    # generate_prom_config(isdas, tp, local_gen_path)


def remove_incomplete_router_info(topo):
    """
    Prevents the incomplete router info being written into the topology file
    if the remote address of the router is not available yet. Remote address
    will be available when a connection request is approved.
    :param dict topo: AS topology as a dictionary
    """
    routers = topo['BorderRouters']
    complete_routers = {}
    complete_flag = True
    for name, router in routers.items():
        for ifid, intf_dict in router['Interfaces'].items():
            if (intf_dict['Remote']['Addr'] == '' or intf_dict['Remote']['L4Port'] == ''):
                complete_flag = False
        if complete_flag:
            complete_routers[name] = router
    topo['BorderRouters'] = complete_routers


def _get_as_obj(isd_as):
    """
    Loads given AS information from DB.
    :param ISD_AS isd_as: ISD the AS belongs to
    :returns obj as_obj: DB information for the AS
    """
    try:
        as_obj = AD.objects.get(isd_id=isd_as[0], as_id=isd_as[1])
    except AD.DoesNotExist:
        logger.error("AS %s was not found." % isd_as)
        return
    return as_obj


def _write_prometheus_config_files(local_gen_path, as_path, elem_dict):
    """
    Helper function to generate all the prometheus config and target files.
    :param str local_gen_path: The gen path of scion-web.
    :param str as_path: The path of the given AS.
    :param dict elem_dict: A dict mapping from element types to target addresses.
    """
    job_dict = {}
    for ele_type, target_list in elem_dict.items():
        targets_path = os.path.join(
            as_path, PrometheusGenerator.PROM_DIR, PrometheusGenerator.TARGET_FILES[ele_type])
        job_dict[PrometheusGenerator.JOB_NAMES[ele_type]] = [targets_path]
        _write_prometheus_target_file(as_path, target_list, ele_type)
    _write_prometheus_config_file(as_path, job_dict)
    # Regenerate the top-level prometheus config file.
    # TODO(shitz): Generation of the top level prometheus file should happen further
    # up and not where the prometheus configuration is done for a single AS. Needs
    # refactoring of the code.
    _generate_toplevel_prom_config(local_gen_path)


def _write_prometheus_config_file(path, job_dict):
    """
    Writes a Prometheus configuration file into the given path
    generates for border routers.
    :param str path: The path to write the configuration file into.
    :param dict job_dict: A dictionary mapping from job name to a list of file
        paths to be provided to file_sd_configs field of the configuration file.
    """
    scrape_configs = []
    for job_name, file_paths in job_dict.items():
        scrape_configs.append({
            'job_name': job_name,
            'file_sd_configs': [{'files': file_paths}],
        })
    config = {
        'global': {
            'scrape_interval': '5s',
            'evaluation_interval': '5s',
            'external_labels': {
                'monitor': 'scion-monitor'
            }
        },
        'scrape_configs': scrape_configs
    }
    write_file(os.path.join(path, PROM_FILE),
               yaml.dump(config, default_flow_style=False))


def _write_prometheus_target_file(base_path, target_addrs, ele_type):
    """
    Writes the target file into the given path.
    :param str base_path: The base path of the target file.
    :param list target_addrs: A list of target addresses.
    :param str ele_type: The type of the infrastructure element.
    """
    targets_path = os.path.join(
        base_path, PrometheusGenerator.PROM_DIR, PrometheusGenerator.TARGET_FILES[ele_type])
    target_config = [{'targets': target_addrs}]
    write_file(targets_path, yaml.dump(target_config, default_flow_style=False))


def _generate_toplevel_prom_config(local_gen_path):
    """
    Generates the top level prometheus config file.
    :param str local_gen_path: The gen path of scion-web.
    """
    job_dict = defaultdict(list)
    all_ases = AD.objects.all()
    for as_obj in all_ases:
        ia = ISD_AS.from_values(as_obj.isd_id, as_obj.as_id)
        for ele_type, target_file in PrometheusGenerator.TARGET_FILES.items():
            targets_path = os.path.join(
                get_elem_dir(local_gen_path, ia, ""), PrometheusGenerator.PROM_DIR, target_file)
            job_dict[PrometheusGenerator.JOB_NAMES[ele_type]].append(targets_path)
    _write_prometheus_config_file(local_gen_path, job_dict)
