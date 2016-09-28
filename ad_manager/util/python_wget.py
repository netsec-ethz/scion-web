#!/usr/bin/env python3
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

# Get config file from server

import os
import subprocess
import tarfile
import urllib.request
import uuid
import xmlrpc.client
from xmlrpc.server import SimpleXMLRPCServer

from lib.defines import PROJECT_ROOT


class PythonRPCInterface(object):
    """
    python xml rpc server which is launched on every AS node.

    It serves as a RPC server for the web management interface and
    as a client to Supervisor.

    TODO: Give class definition parameters description
    """

    def __init__(self):
        """
        Initialize an instance of the class PythonRPCInterface.
        """
        self.id_ = None
        self.management_server_ip = None
        self.isd_name = None
        self.as_name = None
        self.start_rpc_server()  # might want to start it in a separate thread,
        # to run independently of the heartbeat
        # self.start_heartbeat()  # regular status message sent to the server

    def start_rpc_server(self):
        server = SimpleXMLRPCServer(('0.0.0.0', 9012), logRequests=True)
        for f in self.get_rpc_functions():
            server.register_function(f)
        server.register_introspection_functions()
        server.serve_forever()

    def get_rpc_functions(self):
        return [self.control_process,
                self.tail_process_log,
                self.register,
                self.retrieve_configuration
                ]

    def control_process(self, process_name, command, supervisord_ip='127.0.0.1',
                        supervisord_port='9011', wait_for_result=True):
        server = xmlrpc.client.ServerProxy(
            'http://{}:{}'.format(supervisord_ip, supervisord_port))
        succeeded = False
        if command == 'STOP':
            succeeded = server.supervisor.stopProcess(process_name,
                                                      wait_for_result)
        elif command == 'START':
            succeeded = server.supervisor.startProcess(process_name,
                                                       wait_for_result)

        return succeeded

    def tail_process_log(self, process_name, offset=0, length=1000,
                         supervisord_ip='127.0.0.1', supervisord_port='9011'):
        server = xmlrpc.client.ServerProxy(
            'http://{}:{}'.format(supervisord_ip, supervisord_port))
        succeeded = server.supervisor.tailProcessStdoutLog(process_name, offset,
                                                           length)
        return succeeded

    def register(self, management_server_ip, isd_name, as_name):
        self.management_server_ip = management_server_ip
        self.id_ = uuid.uuid1()
        self.isd_name = isd_name
        self.as_name = as_name
        return {'uuid': str(self.id_)}

    def retrieve_configuration(self, id_, management_server_ip, isd_name,
                               as_name):
        process_url = 'http://{}:8000/static/tmp/{}.tar'.format(
            management_server_ip, id_)
        destination = "gen/{}/{}/".format(isd_name, as_name)
        destination = os.path.join(PROJECT_ROOT, destination)
        os.makedirs(destination, exist_ok=True)
        tar_file_path = destination + 'configuration.tar'

        urllib.request.urlretrieve(process_url, filename=tar_file_path)

        with tarfile.open(tar_file_path, 'r:*') as tar_archive:
            #  watch out for malicious tar with .. and / pathes
            tar_archive.extractall(destination)
        # run supervisor/supervisor.sh update
        supervisor_sh_path = os.path.join(PROJECT_ROOT, 'supervisor',
                                          'supervisor.sh')
        res = subprocess.check_call([supervisor_sh_path, 'update'],
                                    cwd=PROJECT_ROOT)
        print(res)
        res = subprocess.check_call([supervisor_sh_path, 'quickstart all'],
                                    cwd=PROJECT_ROOT)
        print(res)
        print('done')
        return 'Succeeded'


if __name__ == "__main__":
    PythonRPCInterface()
