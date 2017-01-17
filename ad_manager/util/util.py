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
import base64
import logging
import requests

# External packages
from django.http import (
    HttpResponse,
    HttpResponseServerError,
)


def to_b64(bytes_input):
    return base64.b64encode(bytes_input).decode()


def from_b64(string_input):
    return base64.b64decode(string_input)


def post_req_to_scion_coord(request_url, request_dict, description):
    """
    Makes a POST request to the SCION Coordination Service.
    param str request_url: The URL for the POST request.
    param dict request_dict: Contents of the request as a dictionary object.
    param str description: A description string of the request to be used
    for logging purposes.
    returns: A tuple containing the response and a Django HTTP error response
    in case an error occurred.
    rtype: (requests.Response, django.http.HttpResponse)
    """

    headers = {'content-type': 'application/json'}
    try:
        r = requests.post(request_url, json=request_dict, headers=headers)
    except requests.RequestException:
        logging.error("Failed to connect to SCION Coordination Service.")
        return None, HttpResponseServerError("Failed to connect to SCION "
                                             "coordination Service.")
    if r.status_code != 200:
        logging.error("Sending %s failed with status code %s", description,
                      r.status_code)
        return None, HttpResponse("Sending %s returned %s" % (description,
                                  r.status_code), status=r.status_code)
    return r, None
