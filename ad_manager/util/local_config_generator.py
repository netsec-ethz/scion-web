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
import configparser
import logging
import os
import yaml
from copy import deepcopy
from shutil import rmtree
from string import Template

# SCION
from lib.defines import (
    AS_CONF_FILE,
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    PATH_SERVICE,
    PROJECT_ROOT,
    PROM_FILE,
    ROUTER_SERVICE,
    SIBRA_SERVICE,
)
from lib.packet.scion_addr import ISD_AS
from lib.util import (
    copy_file,
    get_cert_chain_file_path,
    get_enc_key_file_path,
    get_sig_key_file_path,
    get_trc_file_path,
    read_file,
    write_file,
)
from topology.generator import (
    DEFAULT_PATH_POLICY_FILE,
    INITIAL_CERT_VERSION,
    INITIAL_TRC_VERSION,
    PATH_POLICY_FILE,
)
from topology.generator import PrometheusGenerator

# SCION-WEB
from ad_manager.models import AD


ZOOKEEPER_SERVICE = "zk"  # TODO: make PR to add into lib.defines as it used to
# Scion beacon server
BEACON_EXECUTABLE = "beacon_server"
# Scion certificate server
CERTIFICATE_EXECUTABLE = "cert_server"
# Scion path server
PATH_EXECUTABLE = "path_server"
# Scion sibra server
SIBRA_EXECUTABLE = "sibra_server"
# Scion border router
ROUTER_EXECUTABLE = "router"
# Zookeeper executable
ZOOKEEPER_EXECUTABLE = "zookeeper.jar"

#: All the service types executables
#  TODO: make PR to add into lib.defines as it used to
SERVICE_EXECUTABLES = (
    BEACON_EXECUTABLE,
    CERTIFICATE_EXECUTABLE,
    PATH_EXECUTABLE,
    ROUTER_EXECUTABLE,
    SIBRA_EXECUTABLE,
)

WEB_ROOT = os.path.join(PROJECT_ROOT, 'sub', 'web')
logger = logging.getLogger("scion-web")


def lookup_dict_services_prefixes():
    # looks up the prefix used for naming supervisor processes,
    return {'router': ROUTER_SERVICE,
            'beacon_server': BEACON_SERVICE,
            'path_server': PATH_SERVICE,
            'certificate_server': CERTIFICATE_SERVICE,
            'sibra_server': SIBRA_SERVICE,
            'zookeeper_service': ZOOKEEPER_SERVICE}


def lookup_dict_executables():
    return {'router': ROUTER_EXECUTABLE,
            'beacon_server': BEACON_EXECUTABLE,
            'path_server': PATH_EXECUTABLE,
            'certificate_server': CERTIFICATE_EXECUTABLE,
            'sibra_server': SIBRA_EXECUTABLE,
            'zookeeper_service': ZOOKEEPER_EXECUTABLE}


def create_local_gen(isd_as, tp):
    """
    Creates the usual gen folder structure for an ISD/AS under web_scion/gen,
    ready for Ansible deployment
    :param str isd_as: ISD-AS as a string
    :param dict tp: the topology parameter file as a dict of dicts
    """
    # looks up the name of the executable for the service,
    # certificate server -> 'cert_server', ...
    lkx = lookup_dict_executables()
    isd_id, as_id = ISD_AS(isd_as)
    local_gen_path = os.path.join(WEB_ROOT, 'gen')
    write_dispatcher_config(local_gen_path)
    try:
        as_path = 'ISD{}/AS{}/'.format(isd_id, as_id)
        as_path = os.path.join(local_gen_path, as_path)
        rmtree(as_path, True)
    except OSError:
        pass
    types = ['beacon_server', 'certificate_server', 'router', 'path_server',
             'sibra_server', 'zookeeper_service']
    dict_keys = ['BeaconServers', 'CertificateServers', 'BorderRouters',
                 'PathServers', 'SibraServers', 'Zookeepers']
    types_keys = zip(types, dict_keys)
    zk_name_counter = 1
    for service_type, type_key in types_keys:
        executable_name = lkx[service_type]
        replicas = tp[type_key].keys()  # SECURITY WARNING:allows arbitrary path
        # the user can enter arbitrary paths for his output
        # Mitigation: make path at least relative
        executable_name = os.path.normpath('/'+executable_name).lstrip('/')
        for instance_name in replicas:
            # replace instance_name for zookeeper (they have only ids)
            if service_type == 'zookeeper_service':
                instance_name = 'zk%s-%s-%s' % (isd_id, as_id, zk_name_counter)
                zk_name_counter += 1
            config = prep_supervisord_conf(executable_name, service_type,
                                           instance_name, isd_id, as_id)
            instance_path = 'ISD%s/AS%s/%s' % (isd_id, as_id, instance_name)
            instance_path = os.path.join(local_gen_path, instance_path)
            write_certs_trc_keys(isd_id, as_id, instance_path)
            write_as_conf_and_path_policy(isd_id, as_id, instance_path)
            write_supervisord_config(config, instance_path)
            write_topology_file(tp, type_key, instance_path)
            write_zlog_file(service_type, instance_name, instance_path)
    write_endhost_config(tp, isd_id, as_id, local_gen_path)
    generate_prometheus_config(tp, isd_id, as_id, local_gen_path, as_path)


def topo_instance(tp, type_key):
    #  Little trow away logic handling the NATed case until topo represents
    # internal and external addresses

    singular_topo = deepcopy(tp)
    remove_incomplete_router_info(singular_topo)
    for server_type in singular_topo.keys():  # services know only internal
        if server_type.endswith("Servers") or server_type == 'Zookeepers':
            for entry in singular_topo[server_type]:
                internal_address = singular_topo[server_type][entry].pop(
                    'AddrInternal')
                internal_port = singular_topo[server_type][entry].pop(
                    'PortInternal')
                if type_key in ('BorderRouters', 'endhost'):
                    continue  # Routers and endhost only know about external
                if internal_address != '':
                    singular_topo[server_type][entry]['Addr'] = internal_address
                if internal_port is not None:
                    singular_topo[server_type][entry]['Port'] = internal_port
    return singular_topo


def remove_incomplete_router_info(topo):
    """
    Prevents the incomplete router info being written into the topology file
    if the remote address of the router is not available yet. Remote address
    will be available when a connection request is approved.
    :param dict topo: AS topology as a dictionary
    """
    routers = topo['BorderRouters']
    complete_routers = {}
    for name, router in routers.items():
        if (router['Interface']['ToAddr'] != '' and
                router['Interface']['ToUdpPort'] != ''):
            complete_routers[name] = router
    topo['BorderRouters'] = complete_routers


def prep_supervisord_conf(executable_name, service_type, instance_name,
                          isd_id, as_id):
    """
    Prepares the supervisord configuration for the infrastructure elements
    and returns it as a ConfigParser object.
    :param str executable_name: the name of the executable.
    :param str service_type: the type of the service (e.g. beacon_server).
    :param str instance_name: the instance of the service (e.g. br1-8-1).
    :param str isd_id: the ISD the service belongs to.
    :param str as_id: the AS the service belongs to.
    :returns: supervisord configuration as a ConfigParser object
    :rtype: ConfigParser
    """
    config = configparser.ConfigParser()
    env_tmpl = 'PYTHONPATH=.,ZLOG_CFG="gen/ISD%s/AS%s/%s/%s.zlog.conf"'
    if service_type == 'router':  # go router
        env_tmpl += ',GODEBUG="cgocheck=0"'
        cmd_tmpl = ('bash -c \'exec "bin/border" "-id" "%s" "-confd" '
                    '"gen/ISD%s/AS%s/%s" &>logs/%s.OUT\'')
        cmd = cmd_tmpl % (instance_name, isd_id, as_id,
                          instance_name, instance_name)
    elif service_type == 'zookeeper_service':
        cmd = prep_zk_supervisord_cmd(instance_name, isd_id, as_id)
    else:  # other infrastructure elements
        cmd_tmpl = ('bash -c \'exec "bin/%s" "%s" '
                    '"gen/ISD%s/AS%s/%s" &>logs/%s.OUT\'')
        cmd = cmd_tmpl % (executable_name, instance_name, isd_id, as_id,
                          instance_name, instance_name)
    env = env_tmpl % (isd_id, as_id, instance_name, instance_name)
    config['program:' + instance_name] = {
        'priority': '100',
        'environment': env,
        'stdout_logfile': 'NONE',
        'autostart': 'false',
        'stderr_logfile': 'NONE',
        'command':  cmd,
        'startretries': '0',
        'startsecs': '5',
        'autorestart': 'false'
    }
    return config


def prep_zk_supervisord_cmd(instance_name, isd_id, as_id):
    """
    Generates the supervisord command for Zookeeper instances.
    :param str instance_name: the instance of the service (e.g. zk1-8-1)
    :param str isd_id: the ISD the service belongs to.
    :param str as_id: the AS the service belongs to.
    :returns str: Command section of Zookeeper supervisord config.
    :rtype str
    """
    zk_config_path = os.path.join(PROJECT_ROOT,
                                  'topology',
                                  'Zookeeper.yml')
    zk_config = {}
    with open(zk_config_path, 'r') as stream:
        zk_config = yaml.load(stream)
    class_path = zk_config['Environment']['CLASSPATH']
    zoomain_env = zk_config['Environment']['ZOOMAIN']
    zk_path = "gen/ISD%s/AS%s/%s" % (isd_id, as_id, instance_name)
    class_path = "%s:%s" % (zk_path, class_path)
    log_file = "-Dzookeeper.log.filename=logs/%s.log" % instance_name
    cmd_parts = [
       "java", "-cp", class_path, log_file, '"%s"' % zoomain_env,
       os.path.join(zk_path, "zoo.cfg")
    ]
    return " ".join(cmd_parts)


def prep_dispatcher_supervisord_conf():
    """
    Prepares the supervisord configuration for dispatcher.
    :returns: supervisord configuration as a ConfigParser object
    :rtype: ConfigParser
    """
    config = configparser.ConfigParser()
    env = 'PYTHONPATH=.,ZLOG_CFG="gen/dispatcher/dispatcher.zlog.conf"'
    cmd = """bash -c 'exec bin/dispatcher &>logs/dispatcher.OUT'"""
    config['program:dispatcher'] = {
        'priority': '50',
        'environment': env,
        'stdout_logfile': 'NONE',
        'autostart': 'false',
        'stderr_logfile': 'NONE',
        'command':  cmd,
        'startretries': '0',
        'startsecs': '1',
        'autorestart': 'false'
    }
    return config


def write_topology_file(tp, type_key, instance_path):
    """
    Writes the topology file into the instance's location.
    :param dict tp: the topology as a dict of dicts.
    :param str type_key: key to describe service type.
    :param instance_path: the folder to write the file into.
    """
    path = os.path.join(instance_path, 'topology.yml')
    topo = topo_instance(tp, type_key)
    with open(path, 'w') as file:
        yaml.dump(topo, file, default_flow_style=False)


def write_endhost_config(tp, isd_id, as_id, local_gen_path):
    """
    Writes the endhost folder into the given location.
    :param dict tp: the topology as a dict of dicts.
    :param str isd_id: ISD the AS belongs to.
    :param str as_id: AS for endhost folder will be created.
    :param local_gen_path: the location to create the endhost folder in.
    """
    endhost_path = os.path.join(local_gen_path,
                                'ISD%s/AS%s/%s' % (isd_id, as_id, 'endhost'))
    if not os.path.exists(endhost_path):
        os.makedirs(endhost_path)
    write_certs_trc_keys(isd_id, as_id, endhost_path)
    write_as_conf_and_path_policy(isd_id, as_id, endhost_path)
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


def write_certs_trc_keys(isd_id, as_id, instance_path):
    """
    Writes the certificate and the keys for the given service
    instance of the given AS.
    :param str isd_id: ISD the AS belongs to.
    :param str as_id: AS for which the certs, TRC and keys will be written.
    :param str instance_path: Location (in the file system) to write
    the configuration into.
    """
    try:
        ia = AD.objects.get(isd_id=isd_id, as_id=as_id)
    except AD.DoesNotExist:
        logger.error("AS %s-%s was not found." % (isd_id, as_id))
        return
    # write keys
    sig_path = get_sig_key_file_path(instance_path)
    enc_path = get_enc_key_file_path(instance_path)
    write_file(sig_path, ia.sig_priv_key)
    write_file(enc_path, ia.enc_priv_key)
    # write cert
    cert_chain_path = get_cert_chain_file_path(
        instance_path, ISD_AS.from_values(isd_id, as_id), INITIAL_CERT_VERSION)
    write_file(cert_chain_path, ia.certificate)
    # write trc
    trc_path = get_trc_file_path(instance_path, isd_id, INITIAL_TRC_VERSION)
    write_file(trc_path, ia.trc)


def write_as_conf_and_path_policy(isd_id, as_id, instance_path):
    """
    Writes AS configuration (i.e. as.yml) and path policy files.
    :param str isd_id: ISD the AS belongs to.
    :param str as_id: AS for which the configuration should be written.
    :param str instance_path: Location (in the file system) to write
    the configuration into.
    """
    try:
        ia = AD.objects.get(isd_id=isd_id, as_id=as_id)
    except AD.DoesNotExist:
        logger.error("AS %s-%s was not found." % (isd_id, as_id))
        return
    conf = {
        'MasterASKey': ia.master_as_key,
        'RegisterTime': 5,
        'PropagateTime': 5,
        'CertChainVersion': 0,
        'RegisterPath': True,
    }
    conf_file = os.path.join(instance_path, AS_CONF_FILE)
    write_file(conf_file, yaml.dump(conf, default_flow_style=False))
    path_policy_file = os.path.join(PROJECT_ROOT, DEFAULT_PATH_POLICY_FILE)
    copy_file(path_policy_file, os.path.join(instance_path, PATH_POLICY_FILE))


def generate_prometheus_config(tp, isd_id, as_id, local_gen_path, as_path):
    """
    Writes Prometheus configuration files for the given AS. Currently only
    generates for border routers.
    :param dict tp: the topology of the AS provided as a dict of dicts.
    :param str isd_id: ISD the AS belongs to.
    :param str as_id: AS for which the configuration should be written.
    :param str local_gen_path: The gen path of scion-web.
    :param str as_path: The path of the given AS.
    """
    ia = ISD_AS.from_values(isd_id, as_id)
    router_list = []
    routers = tp['BorderRouters']
    for _, router in routers.items():
        router_list.append("%s:%s" % (router['Addr'], router['Port']))
    targets_path = os.path.join(as_path, PrometheusGenerator.PROM_DIR,
                                PrometheusGenerator.BR_TARGET_FILE)
    target_config = [{'targets': router_list}]
    write_file(targets_path, yaml.dump(target_config, default_flow_style=False))
    write_prometheus_config_file(local_gen_path, [targets_path])
    # Create the config for the top level gen directory as well.
    file_paths = []
    all_ases = AD.objects.all()
    for as_obj in all_ases:
        targets_path = os.path.join(
            local_gen_path, "ISD%s" % as_obj.isd_id, "AS%s" % as_obj.as_id,
            PrometheusGenerator.PROM_DIR, PrometheusGenerator.BR_TARGET_FILE)
        file_paths.append(targets_path)
    write_prometheus_config_file(local_gen_path, file_paths)


def write_prometheus_config_file(path, file_paths):
    """
    Writes a Prometheus configuration file into the given path
    generates for border routers.
    :param str path: The path to write the configuration file into.
    :param list file_paths: A list of file paths to be provided to
    file_sd_configs field of the configuration file.
    """
    config = {
        'global': {
            'scrape_interval': '5s',
            'evaluation_interval': '15s',
            'external_labels': {
                'monitor': 'scion-monitor'
            }
        },
        'scrape_configs': [{
            'job_name': 'border',
            'file_sd_configs': [{'files': file_paths}]
        }],
    }
    write_file(os.path.join(path, PROM_FILE),
               yaml.dump(config, default_flow_style=False))
