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

# StdLib
from ipaddress import ip_address


def is_private_address(ip_addr):
    ip_addr = ip_address(ip_addr)
    return str(ip_addr).startswith('127.')


def empty_dict():
    """
    Needed for default value of JSONField.

    :return: empty dictionary
    :rtype: dict
    """
    return {}
