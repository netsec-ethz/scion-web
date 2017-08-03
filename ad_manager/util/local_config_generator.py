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
from topology.generator import PrometheusGenerator

# SCION-WEB
from ad_manager.models import AD
from ad_manager.util.defines import PROM_PORT_OFFSET
from ad_manager.util.simple_config.simple_config import check_simple_conf_mode
from ad_manager.util.local_config_util import (
    generate_zk_config,
    get_elem_dir,
    prep_supervisord_conf,
    TYPES_TO_EXECUTABLES,
    TYPES_TO_KEYS,
    write_as_conf_and_path_policy,
    write_certs_trc_keys,
    write_dispatcher_config,
    write_supervisord_config,
    write_topology_file,
    write_zlog_file,
)

WEB_ROOT = os.path.join(PROJECT_ROOT, 'sub', 'web')
logger = logging.getLogger("scion-web")


def create_local_gen(isdas, tp):
    """
    Creates the usual gen folder structure for an ISD/AS under web_scion/gen,
    ready for Ansible deployment
    :param str isdas: ISD-AS as a string
    :param dict tp: the topology parameter file as a dict of dicts
    """
    ia = ISD_AS(isdas)
    as_obj = _get_as_obj(ia)
    check_simple_conf_mode(tp, ia[0], ia[1])
    local_gen_path = os.path.join(WEB_ROOT, 'gen')
    write_dispatcher_config(local_gen_path)
    as_path = 'ISD%s/AS%s/' % (ia[0], ia[1])
    as_path = get_elem_dir(local_gen_path, ia, "")
    rmtree(as_path, True)
    for service_type, type_key in TYPES_TO_KEYS.items():
        executable_name = TYPES_TO_EXECUTABLES[service_type]
        instances = tp[type_key].keys()
        for instance_name in instances:
            config = prep_supervisord_conf(tp[type_key][instance_name], executable_name,
                                           service_type, instance_name, ia)
            instance_path = get_elem_dir(local_gen_path, ia, instance_name)
            write_certs_trc_keys(ia, as_obj, instance_path)
            write_as_conf_and_path_policy(ia, as_obj, instance_path)
            write_supervisord_config(config, instance_path)
            write_topology_file(tp, type_key, instance_path)
            write_zlog_file(service_type, instance_name, instance_path)
    write_endhost_config(tp, ia, as_obj, local_gen_path)
    generate_zk_config(tp, ia, local_gen_path, as_obj.simple_conf_mode)
    generate_prometheus_config(tp, local_gen_path, as_path)


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


def write_endhost_config(tp, isd_as, as_obj, local_gen_path):
    """
    Writes the endhost folder into the given location.
    :param dict tp: the topology as a dict of dicts.
    :param ISD_AS isd_as: ISD the AS belongs to.
    :param local_gen_path: the location to create the endhost folder in.
    """
    endhost_path = get_elem_dir(local_gen_path, isd_as, 'endhost')
    if not os.path.exists(endhost_path):
        os.makedirs(endhost_path)
    write_certs_trc_keys(isd_as, as_obj, endhost_path)
    write_as_conf_and_path_policy(isd_as, as_obj, endhost_path)
    write_topology_file(tp, 'endhost', endhost_path)


def _get_as_obj(isd_as):
    """
    Loads given AS information from DB.
    :param ISD_AS isd_as: ISD the AS belongs to
    :returns obj as_obj: DB information for the AS
    """
    try:
        as_obj = AD.objects.get(isd_id=isd_as[0], as_id=isd_as[1])
    except AD.DoesNotExist:
        logger.error("AS %s-%s was not found." % (isd_as[0], isd_as[1]))
        return
    return as_obj


def generate_prometheus_config(tp, local_gen_path, as_path):
    """
    Writes Prometheus configuration files for the given AS.
    :param dict tp: the topology of the AS provided as a dict of dicts.
    :param str local_gen_path: The gen path of scion-web.
    :param str as_path: The path of the given AS.
    """
    elem_dict = defaultdict(list)
    for br_id, br_elem in tp['BorderRouters'].items():
        for int_addrs in br_elem['InternalAddrs']:
            for addr_info in int_addrs['Public']:
                prom_addr = "%s:%s" % (addr_info['Addr'], addr_info['L4Port'] + PROM_PORT_OFFSET)
                elem_dict['BorderRouters'].append(prom_addr)
    for svc_type in ['BeaconService', 'PathService', 'CertificateService']:
        for elem_id, elem in tp[svc_type].items():
            for addr_info in elem['Public']:
                prom_addr = "%s:%s" % (addr_info['Addr'], addr_info['L4Port'] + PROM_PORT_OFFSET)
                elem_dict[svc_type].append(prom_addr)
    _write_prometheus_config_files(local_gen_path, as_path, elem_dict)


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
