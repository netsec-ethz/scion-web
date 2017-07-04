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
from collections import defaultdict
import configparser
import json
import logging
import os
import yaml
from shutil import rmtree
from string import Template

# External packages
from django.shortcuts import get_object_or_404

# SCION
from lib.crypto.asymcrypto import (
    get_enc_key_file_path,
    get_sig_key_file_path,
)
from lib.crypto.certificate_chain import get_cert_chain_file_path
from lib.crypto.trc import get_trc_file_path
from lib.defines import (
    AS_CONF_FILE,
    GEN_PATH,
    PROJECT_ROOT,
    PROM_FILE,
)
from lib.packet.scion_addr import ISD_AS
from lib.util import (
    copy_file,
    read_file,
    write_file,
)
from topology.generator import (
    DEFAULT_PATH_POLICY_FILE,
    INITIAL_CERT_VERSION,
    INITIAL_TRC_VERSION,
    PATH_POLICY_FILE,
)
from topology.generator import PrometheusGenerator, _topo_json_to_yaml

# SCION-WEB
from ad_manager.models import AD
from ad_manager.util.simple_config.simple_config import check_simple_conf_mode
from ad_manager.util.defines import PROM_PORT_OFFSET

WEB_ROOT = os.path.join(PROJECT_ROOT, 'sub', 'web')
logger = logging.getLogger("scion-web")

TYPES_TO_EXECUTABLES = {
    'router': 'border',
    'beacon_server': 'beacon_server',
    'path_server': 'path_server',
    'certificate_server': 'cert_server',
    'sibra_server': 'sibra_server'
}

TYPES_TO_KEYS = {
    'beacon_server': 'BeaconService',
    'certificate_server': 'CertificateService',
    'router': 'BorderRouters',
    'path_server': 'PathService',
    'sibra_server': 'SibraService'
}


def create_local_gen(isdas, tp):
    """
    Creates the usual gen folder structure for an ISD/AS under web_scion/gen,
    ready for Ansible deployment
    :param str isdas: ISD-AS as a string
    :param dict tp: the topology parameter file as a dict of dicts
    """
    ia = ISD_AS(isdas)
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
            write_certs_trc_keys(ia, instance_path)
            write_as_conf_and_path_policy(ia, instance_path)
            write_supervisord_config(config, instance_path)
            write_topology_file(tp, type_key, instance_path)
            write_zlog_file(service_type, instance_name, instance_path)
    write_endhost_config(tp, ia, local_gen_path)
    generate_zk_config(tp, ia, local_gen_path)
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


def prep_supervisord_conf(instance_dict, executable_name, service_type, instance_name, isd_as):
    """
    Prepares the supervisord configuration for the infrastructure elements
    and returns it as a ConfigParser object.
    :param dict instance_dict: topology information of the given instance.
    :param str executable_name: the name of the executable.
    :param str service_type: the type of the service (e.g. beacon_server).
    :param str instance_name: the instance of the service (e.g. br1-8-1).
    :param ISD_AS isd_as: the ISD-AS the service belongs to.
    :returns: supervisord configuration as a ConfigParser object
    :rtype: ConfigParser
    """
    config = configparser.ConfigParser()
    env_tmpl = 'PYTHONPATH=python:.,ZLOG_CFG="%s/%s.zlog.conf"'
    if service_type == 'router':  # go router
        env_tmpl += ',GODEBUG="cgocheck=0"'
        prom_addr = "%s:%s" % (instance_dict['InternalAddrs'][0]['Public'][0]['Addr'],
                               instance_dict['InternalAddrs'][0]['Public'][0]['L4Port'] +
                               PROM_PORT_OFFSET)
        cmd = ('bash -c \'exec bin/%s -id "%s" -confd "%s" -prom "%s" &>logs/%s.OUT\'') % (
            executable_name, instance_name, get_elem_dir(GEN_PATH, isd_as, instance_name),
            prom_addr, instance_name)
    else:  # other infrastructure elements
        prom_addr = "%s:%s" % (instance_dict['Public'][0]['Addr'],
                               instance_dict['Public'][0]['L4Port'] + PROM_PORT_OFFSET)
        cmd = ('bash -c \'exec bin/%s "%s" "%s" --prom "%s" &>logs/%s.OUT\'') % (
            executable_name, instance_name, get_elem_dir(GEN_PATH, isd_as, instance_name),
            prom_addr, instance_name)
    env = env_tmpl % (get_elem_dir(GEN_PATH, isd_as, instance_name),
                      instance_name)
    config['program:' + instance_name] = {
        'autostart': 'false',
        'autorestart': 'false',
        'environment': env,
        'stdout_logfile': 'NONE',
        'stderr_logfile': 'NONE',
        'startretries': '0',
        'startsecs': '5',
        'priority': '100',
        'command':  cmd
    }
    return config


def get_elem_dir(path, isd_as, elem_id):
    """
    Generates and returns the directory of a SCION element.
    :param str path: Relative or absolute path.
    :param ISD_AS isd_as: ISD-AS to which the element belongs.
    :param elem_id: The name of the instance.
    :returns: The directory of the instance.
    :rtype: string
    """
    return "%s/ISD%s/AS%s/%s" % (path, isd_as[0], isd_as[1], elem_id)


def prep_dispatcher_supervisord_conf():
    """
    Prepares the supervisord configuration for dispatcher.
    :returns: supervisord configuration as a ConfigParser object
    :rtype: ConfigParser
    """
    config = configparser.ConfigParser()
    env = 'PYTHONPATH=python:.,ZLOG_CFG="gen/dispatcher/dispatcher.zlog.conf"'
    cmd = """bash -c 'exec bin/dispatcher &>logs/dispatcher.OUT'"""
    config['program:dispatcher'] = {
        'autostart': 'false',
        'autorestart': 'false',
        'environment': env,
        'stdout_logfile': 'NONE',
        'stderr_logfile': 'NONE',
        'startretries': '0',
        'startsecs': '1',
        'priority': '50',
        'command':  cmd
    }
    return config


def write_topology_file(tp, type_key, instance_path):
    """
    Writes the topology file into the instance's location.
    :param dict tp: the topology as a dict of dicts.
    :param str type_key: key to describe service type.
    :param instance_path: the folder to write the file into.
    """
    path = os.path.join(instance_path, 'topology.json')
    with open(path, 'w') as file:
        json.dump(tp, file, indent=2)
    topo_yml = _topo_json_to_yaml(tp)
    path = os.path.join(instance_path, 'topology.yml')
    with open(path, 'w') as file:
        yaml.dump(topo_yml, file, default_flow_style=False)


def write_endhost_config(tp, isd_as, local_gen_path):
    """
    Writes the endhost folder into the given location.
    :param dict tp: the topology as a dict of dicts.
    :param ISD_AS isd_as: ISD the AS belongs to.
    :param local_gen_path: the location to create the endhost folder in.
    """
    endhost_path = get_elem_dir(local_gen_path, isd_as, 'endhost')
    if not os.path.exists(endhost_path):
        os.makedirs(endhost_path)
    write_certs_trc_keys(isd_as, endhost_path)
    write_as_conf_and_path_policy(isd_as, endhost_path)
    write_topology_file(tp, 'endhost', endhost_path)


def write_dispatcher_config(local_gen_path):
    """
    Creates the supervisord and zlog files for the dispatcher and writes
    them into the dispatcher folder.
    :param str local_gen_path: the location to create the dispatcher folder in.
    """
    disp_folder_path = os.path.join(local_gen_path, 'dispatcher')
    if not os.path.exists(disp_folder_path):
        os.makedirs(disp_folder_path)
    disp_supervisord_conf = prep_dispatcher_supervisord_conf()
    write_supervisord_config(disp_supervisord_conf, disp_folder_path)
    write_zlog_file('dispatcher', 'dispatcher', disp_folder_path)


def write_zlog_file(service_type, instance_name, instance_path):
    """
    Creates and writes the zlog configuration file for the given element.
    :param str service_type: the type of the service (e.g. beacon_server).
    :param str instance_name: the instance of the service (e.g. br1-8-1).
    """
    tmpl = Template(read_file(os.path.join(PROJECT_ROOT,
                                           "topology/zlog.tmpl")))
    cfg = os.path.join(instance_path, "%s.zlog.conf" % instance_name)
    write_file(cfg, tmpl.substitute(name=service_type,
                                    elem=instance_name))


def write_supervisord_config(config, instance_path):
    """
    Writes the given supervisord config into the provided location.
    :param ConfigParser config: supervisord configuration to write.
    :param instance_path: the folder to write the config into.
    """
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
    conf_file_path = os.path.join(instance_path, 'supervisord.conf')
    with open(conf_file_path, 'w') as configfile:
        config.write(configfile)


def write_certs_trc_keys(isd_as, instance_path):
    """
    Writes the certificate and the keys for the given service
    instance of the given AS.
    :param ISD_AS isd_as: ISD the AS belongs to.
    :param str instance_path: Location (in the file system) to write
    the configuration into.
    """
    try:
        as_obj = AD.objects.get(isd_id=isd_as[0], as_id=isd_as[1])
    except AD.DoesNotExist:
        logger.error("AS %s-%s was not found." % (isd_as[0], isd_as[1]))
        return
    # write keys
    sig_path = get_sig_key_file_path(instance_path)
    enc_path = get_enc_key_file_path(instance_path)
    write_file(sig_path, as_obj.sig_priv_key)
    write_file(enc_path, as_obj.enc_priv_key)
    # write cert
    cert_chain_path = get_cert_chain_file_path(
        instance_path, isd_as, INITIAL_CERT_VERSION)
    write_file(cert_chain_path, as_obj.certificate)
    # write trc
    trc_path = get_trc_file_path(instance_path, isd_as[0], INITIAL_TRC_VERSION)
    write_file(trc_path, as_obj.trc)


def write_as_conf_and_path_policy(isd_as, instance_path):
    """
    Writes AS configuration (i.e. as.yml) and path policy files.
    :param ISD_AS isd_as: ISD-AS for which the config will be written.
    :param str instance_path: Location (in the file system) to write
    the configuration into.
    """
    try:
        as_obj = AD.objects.get(isd_id=isd_as[0], as_id=isd_as[1])
    except AD.DoesNotExist:
        logger.error("AS %s-%s was not found." % (isd_as[0], isd_as[1]))
        return
    conf = {
        'MasterASKey': as_obj.master_as_key,
        'RegisterTime': 5,
        'PropagateTime': 5,
        'CertChainVersion': 0,
        'RegisterPath': True,
    }
    conf_file = os.path.join(instance_path, AS_CONF_FILE)
    write_file(conf_file, yaml.dump(conf, default_flow_style=False))
    path_policy_file = os.path.join(PROJECT_ROOT, DEFAULT_PATH_POLICY_FILE)
    copy_file(path_policy_file, os.path.join(instance_path, PATH_POLICY_FILE))


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

def generate_zk_config(tp, isd_as, local_gen_path):
    """
    Generates Zookeeper configuration files for Zookeeper instances of an AS.
    :param dict tp: the topology of the AS provided as a dict of dicts.
    :param ISD_AS isd_as: ISD-AS for which the ZK config will be written.
    :param str local_gen_path: The gen path of scion-web.
    """
    for zk_id, zk in tp['ZookeeperService'].items():
        instance_name = 'zk%s-%s-%s' % (isd_as[0], isd_as[1], zk_id)
        write_zk_conf(local_gen_path, isd_as, instance_name, zk)


def write_zk_conf(local_gen_path, isd_as, instance_name, zk):
    """
    Writes a Zookeeper configuration file for the given Zookeeper instance.
    :param str local_gen_path: The gen path of scion-web.
    :param ISD_AS isd_as: ISD-AS for which the ZK config will be written.
    :param str instance_name: the instance of the ZK service (e.g. zk1-5-1).
    :param dict zk: Zookeeper instance information from the topology as a
    dictionary.
    """
    as_obj = get_object_or_404(AD, isd_id=isd_as[0], as_id=isd_as[1])
    conf = {
        'tickTime': 100,
        'initLimit': 10,
        'syncLimit': 5,
        'dataDir': '/var/lib/zookeeper',
        'clientPort': zk['L4Port'],
        'maxClientCnxns': 0,
        'autopurge.purgeInterval': 1
    }
    if as_obj.simple_conf_mode:
        conf['clientPortAddress'] = '127.0.0.1'
    else:
        # set the dataLogDir only if we are operating in the normal mode.
        conf['dataLogDir'] = '/run/shm/host-zk'

    zk_conf_path = get_elem_dir(local_gen_path, isd_as, instance_name)
    zk_conf_file = os.path.join(zk_conf_path, 'zoo.cfg')
    write_file(zk_conf_file, yaml.dump(conf, default_flow_style=False))
