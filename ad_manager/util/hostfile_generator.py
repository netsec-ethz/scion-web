# Stdlib
import configparser
import os

from lib.defines import (BEACON_SERVICE,
                         CERTIFICATE_SERVICE,
                         DNS_SERVICE,
                         PATH_SERVICE,
                         ROUTER_SERVICE,
                         SIBRA_SERVICE,
                         PROJECT_ROOT)

ZOOKEEPER_SERVICE = "zk"  # TODO: make PR to add into lib.defines as it used to
WEB_ROOT = os.path.join(PROJECT_ROOT, 'sub', 'web')

SUPPORTED_CLOUD_ENGINES = ['switch_engines', 'amazon_ec2']


def add_new_section(config, section_name):
    try:
        config.add_section(section_name)
    except configparser.DuplicateSectionError:
        pass  # section already exists


def fill_section(config, section_name, val, tags, hostname):
    server_index = 0
    add_new_section(config, section_name)
    for entry in val:
        server_index += 1
        entry = entry.split('/')[0]  # remove subnet size
        config[section_name][entry] = tags + '={} # {}'.format(server_index,
                                                               hostname)


def set_cloud_providers(config, topology_params):
    try:
        addresses = topology_params.getlist('inputCloudAddress')
        providers = topology_params.getlist('inputCloudEngine')
        for provider in SUPPORTED_CLOUD_ENGINES:
            if provider in providers:
                add_new_section(config, provider)
                # a direct mask would be more efficient
                section_values = filter(
                    None, map(lambda matched:
                              matched[0] if matched[1] == provider else None,
                              zip(addresses, providers)
                              )
                )
                for ip in section_values:
                    config.set(provider, ip)
    except KeyError:
        # There are no IPs with a selected cloud provider so the previous
        # section is superfluous
        pass


def generate_ansible_hostfile(topology_params, isd_as):
    """
    Generate the host file for Ansible
    The hostfile is per AS and can have the same IP in multiple roles
    """
    # Write Ansible hostfile
    config = configparser.ConfigParser(allow_no_value=True, delimiters=' ',
                                       inline_comment_prefixes='#')
    isd_id, as_id = isd_as.split('-')
    host_file_path = os.path.join(WEB_ROOT, 'gen',
                                  'ISD' + str(isd_id), 'AS' + str(as_id),
                                  'host.{}-{}'.format(isd_id, as_id))
    # looks up the prefix used for naming supervisor processes,
    # beacon server -> 'bs', ...
    lkp = lookup_dict_services_prefixes()

    scion_nodes = []  # entries for the scion_node section
    for key, service_type in [('BeaconServer', 'beacon_server'),
                              ('CertificateServer', 'cert_server'),
                              #  ('DomainServer', 'dns_server'), # tmp fix
                              # until the discovery replaces it
                              ('EdgeRouter', 'router'),
                              ('PathServer', 'path_server'),
                              ('SibraServer', 'sibra_server'),
                              ('ZookeeperServer', 'zookeeper_service')]:
        val = topology_params.getlist('input' + key + 'Address')
        hostname = topology_params['input' + key + 'Name']
        if service_type.endswith('_server'):
            section_name = service_type + 's'
            tags = 'isd={} as={} {}'.format(isd_id, as_id,
                                            lkp[service_type])
            fill_section(config, section_name, val, tags, hostname)
        elif service_type == 'router':
            remote_isd, remote_as = topology_params[
                'inputInterfaceRemoteName'].split('-')
            section_name = 'edge_routers'
            tags = 'isd={} as={} to_isd={}' \
                ' to_as={} {}'.format(isd_id,
                                      as_id,
                                      remote_isd,
                                      remote_as,
                                      lkp[service_type])
            fill_section(config, section_name, val, tags, hostname)
        elif service_type == 'zookeeper_service':
            section_name = 'zookeepers'
            tags = 'isd={} as={} {}'.format(isd_id,
                                            as_id,
                                            lkp[service_type])
            fill_section(config, section_name, val, tags, hostname)
            continue  # zookeepers are not to be listed in scion_nodes children
        scion_nodes.append(section_name)

    add_new_section(config, 'scion_nodes:children')
    for role in scion_nodes:
        config.set('scion_nodes:children', role)

    # set cloud providers sections
    set_cloud_providers(config, topology_params)

    add_new_section(config, 'scion_nodes:vars')
    local_gen_path = os.path.join(WEB_ROOT, 'gen')
    config.set('scion_nodes:vars', 'local_gen={}'.format(local_gen_path))

    with open(host_file_path, 'w') as configfile:
        config.write(configfile, space_around_delimiters=False)


def lookup_dict_services_prefixes():
    # looks up the prefix used for naming supervisor processes,
    # beacon server -> 'bs', ...
    # TODO: agree on standard service type naming,
    # unify with lookup_dict_services_prefixes function in views
    return {'router': ROUTER_SERVICE,
            'beacon_server': BEACON_SERVICE,
            'path_server': PATH_SERVICE,
            'cert_server': CERTIFICATE_SERVICE,
            'dns_server': DNS_SERVICE,
            'sibra_server': SIBRA_SERVICE,
            'zookeeper_service': ZOOKEEPER_SERVICE}
