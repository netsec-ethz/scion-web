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


def fill_section(config, section_name, val, tags, hostname_lookup):
    server_index = 0
    add_new_section(config, section_name)
    for entry in val:
        server_index += 1
        entry = entry.split('/')[0]  # remove subnet size
        try:
            hostname = hostname_lookup[entry]
        except KeyError:
            hostname = ''  # no hostname defined
        config[section_name][entry] = tags + '={} # {}'.format(server_index,
                                                               hostname)


def fill_router_section(config, section_name, val, remote_isd_as,
                        base_tags, prefix, hostname_lookup):
    server_index = 0
    add_new_section(config, section_name)
    remote_isd, remote_as = zip(
        *map(lambda ip: ip.split('-'), remote_isd_as)
    )
    for entry in val:
        tags = base_tags + 'to_isd={}' ' to_as={} {}'.format(
            remote_isd[server_index],
            remote_as[server_index],
            prefix)
        server_index += 1
        entry = entry.split('/')[0]  # remove subnet size
        try:
            hostname = hostname_lookup[entry]
        except KeyError:
            hostname = ''  # no hostname defined
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


def get_section_attr(mockup_dict, section_name, attr):
    return [server[attr] for server in mockup_dict[section_name].values()]


def generate_ansible_hostfile(topology_params, mockup_dict, isd_as):
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
                              ('BorderRouter', 'router'),
                              ('PathServer', 'path_server'),
                              ('SibraServer', 'sibra_server'),
                              ('Zookeeper', 'zookeeper_service')]:
        val = get_section_attr(mockup_dict, key+'s', 'Addr')
        hostnames = topology_params.getlist('inputHostname')
        unique_addr = topology_params.getlist('inputCloudAddress')
        hostname_lookup = dict(zip(unique_addr, hostnames))
        if service_type.endswith('_server'):
            section_name = service_type + 's'
            tags = 'isd={} as={} {}'.format(isd_id, as_id,
                                            lkp[service_type])
            fill_section(config, section_name, val, tags, hostname_lookup)
        elif service_type == 'router':
            interfaces = get_section_attr(mockup_dict, key+'s', 'Interface')
            remote_isd_as = [x['ISD_AS'] for x in interfaces]
            section_name = 'border_routers'
            tags = 'isd={} as={} '.format(isd_id,
                                          as_id)
            fill_router_section(config, section_name, val, remote_isd_as,
                                tags, lkp[service_type], hostname_lookup)
        elif service_type == 'zookeeper_service':
            section_name = 'zookeepers'
            tags = 'isd={} as={} {}'.format(isd_id,
                                            as_id,
                                            lkp[service_type])
            fill_section(config, section_name, val, tags, hostname_lookup)
            continue  # zookeepers are not to be listed in scion_nodes children
        scion_nodes.append(section_name)

    add_new_section(config, 'scion_nodes:children')
    for role in scion_nodes:
        config.set('scion_nodes:children', role)

    # set cloud providers sections
    set_cloud_providers(config, topology_params)

    # environment variables
    add_new_section(config, 'scion_nodes:vars')
    local_gen_path = os.path.join(WEB_ROOT, 'gen')
    config.set('scion_nodes:vars', 'local_gen={}'.format(local_gen_path))
    config.set('scion_nodes:vars', 'scion_version={}'.format(''))

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
