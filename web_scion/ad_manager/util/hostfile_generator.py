# Stdlib
import configparser
from lib.defines import *


def generate_ansible_hostfile(topology_params, isd_as, lkp):
    """
    Generate the host file for Ansible
    The hostfile is per AS and can have the same IP in multiple roles
    """
    # Write Ansible hostfile
    config = configparser.ConfigParser(allow_no_value=True, delimiters=' ', inline_comment_prefixes='#')
    ansible_path = os.path.join(PROJECT_ROOT, 'ansible')
    conf_file_path = os.path.join(ansible_path, 'GenAnsible.yml')

    isd_id, as_id = isd_as.split('-')
    # looks up the prefix used for naming supervisor processes, beacon server -> 'bs', ...

    scion_nodes = []  # entries for the scion_node section
    for key, section in [('BeaconServer', 'beacon_server'), ('CertificateServer', 'certificate_server'),
                         ('DomainServer', 'domain_server'), ('EdgeRouter', 'router'),
                         ('PathServer', 'path_server'), ('SibraServer', 'sibra_server')]:
        val = [topology_params['input' + key + 'Address']]
        hostname = topology_params['input' + key + 'Name']
        server_index = 0
        for entry in val:
            server_index += 1
            config[section + 's'] =\
                {entry: 'isd={} as={} {}={} # {}'.format(isd_id, as_id, lkp[section], server_index, hostname)}
        scion_nodes.append(section)

    config['scion_nodes:children'] = {}
    for role in scion_nodes:
        config.set('scion_nodes:children', role)

    with open(conf_file_path, 'w') as configfile:
        config.write(configfile, space_around_delimiters=False)
