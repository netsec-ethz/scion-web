# Stdlib
import configparser
from lib.defines import *


def generate_ansible_hostfile(topology_params, isd_as):
    """
    Generate the host file for Ansible
    The hostfile is per AS and can have the same IP in multiple roles
    """
    # Write Ansible hostfile
    config = configparser.ConfigParser(allow_no_value=True, delimiters=' ',
                                       inline_comment_prefixes='#')
    isd_id, as_id = isd_as.split('-')
    host_file_path = os.path.join(PROJECT_ROOT, 'web_scion', 'gen',
                                  'ISD' + str(isd_id), 'AS' + str(as_id),
                                  'hostfile.yml')
    # looks up the prefix used for naming supervisor processes,
    # beacon server -> 'bs', ...
    lkp = lookup_dict_services_prefixes()

    scion_nodes = []  # entries for the scion_node section
    for key, service_type in [('BeaconServer', 'beacon_server'),
                              ('CertificateServer', 'cert_server'),
                              ('DomainServer', 'dns_server'),
                              ('EdgeRouter', 'router'),
                              ('PathServer', 'path_server'),
                              ('SibraServer', 'sibra_server')]:
        val = [topology_params['input' + key + 'Address']]
        hostname = topology_params['input' + key + 'Name']
        server_index = 0
        for entry in val:
            server_index += 1
            entry = entry.split('/')[0]  # remove subnet size
            if service_type != 'router':
                section_name = service_type + 's'
                config[section_name] = \
                    {entry: 'isd={} as={} {}={} # {}'.format(isd_id, as_id,
                                                             lkp[service_type],
                                                             server_index,
                                                             hostname)}
            else:
                remote_isd, remote_as = topology_params[
                    'inputInterfaceRemoteName'].split('-')
                config['edge_routers'] = \
                    {entry: 'isd={} as={} to_isd={} to_as={} {}={} # {}'.format(
                        isd_id,
                        as_id,
                        remote_isd,
                        remote_as,
                        lkp[service_type],
                        server_index,
                        hostname)}
        scion_nodes.append(section_name)

    config['scion_nodes:children'] = {}
    for role in scion_nodes:
        config.set('scion_nodes:children', role)

    config['scion_nodes:vars'] = {}
    local_gen_path = os.path.join(PROJECT_ROOT, 'web_scion', 'gen')
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
