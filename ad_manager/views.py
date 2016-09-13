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
import hashlib
import json
import os
import random
import tempfile
import time
from collections import deque
from shutil import rmtree

# External packages
from urllib.parse import urljoin
from functools import reduce

from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.db import transaction
from django.http import (
    HttpResponse,
    HttpResponseForbidden,
    HttpResponseNotFound,
    JsonResponse,
)
from django.shortcuts import redirect, get_object_or_404, render
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_POST
from django.views.generic import ListView, DetailView, FormView

import yaml
import tarfile
import configparser
import xmlrpc.client
import socket
from copy import deepcopy
from string import Template

import requests

# SCION
from guardian.shortcuts import assign_perm
from ad_manager.util.response_handling import (
    get_failure_errors,
    get_success_data,
    is_success,
)
from ad_manager.util.util import to_b64, from_b64
from ad_manager.util.defines import (
    DEFAULT_BANDWIDTH,
    SCION_SUGGESTED_PORT,
    COORD_SERVICE_URI,
    UPLOAD_JOIN_REQUEST_SVC,
    UPLOAD_JOIN_REPLIES_SVC,
    POLL_JOIN_REPLY_SVC,
    POLL_JOIN_REPLIES_SVC,
    UPLOAD_CONN_REQUESTS_SVC,
    UPLOAD_CONN_REPLIES_SVC,
    POLL_CONN_REPLIES_SVC,
    POLL_EVENTS_SVC,
    INSERT_AS,
    INITIAL_CERT_VERSION
)
from ad_manager.forms import (
    ConnectionRequestForm,
    CoordinationServiceSettingsForm,
    NewLinkForm,
    UploadFileForm
)
from ad_manager.models import AD, ISD, ConnectionRequest,\
    OrganisationAdmin, User, JoinRequest
from ad_manager.util.ad_connect import (
    create_new_ad_files,
    find_last_router,
    # link_ads,
)
from ad_manager.util.errors import HttpResponseUnavailable
from lib.util import (
    read_file,
    write_file
)
from topology.generator import ConfigGenerator  # , DEFAULT_PATH_POLICY_FILE,
# DEFAULT_ZK_CONFIG
from lib.crypto.certificate import Certificate
from lib.util import iso_timestamp
from lib.crypto.asymcrypto import (
    generate_sign_keypair,
    generate_enc_keypair,
    sign
)
from lib.defines import (BEACON_SERVICE,
                         CERTIFICATE_SERVICE,
                         PATH_SERVICE,
                         ROUTER_SERVICE,
                         SIBRA_SERVICE)
from lib.defines import DEFAULT_MTU
from lib.defines import GEN_PATH, PROJECT_ROOT

from ad_manager.util.hostfile_generator import generate_ansible_hostfile
from scripts.reload_data import reload_data_from_files

import subprocess
from shutil import copy, copytree

GEN_PATH = os.path.join(PROJECT_ROOT, GEN_PATH)
WEB_ROOT = os.path.join(PROJECT_ROOT, 'sub', 'web')  # TODO:fix import all paths
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


class ISDListView(ListView):
    model = ISD
    paginate_by = 8


@require_POST
def add_isd(request):
    new_isd_id = request.POST['inputISDname']
    try:
        new_isd_id = int(new_isd_id)
    except ValueError:
        return JsonResponse({'data': 'Invalid ISD id'})
    isd = ISD(id=new_isd_id)
    isd.save()
    current_page = request.META.get('HTTP_REFERER')
    return redirect(current_page)


class ISDDetailView(ListView):
    model = AD
    template_name = 'ad_manager/isd_detail.html'
    paginate_by = 20

    def __init__(self, **kwargs):
        self.isd = None
        super().__init__(**kwargs)

    def get_queryset(self):
        isd = get_object_or_404(ISD, id=int(self.kwargs['pk']))
        self.isd = isd
        queryset = isd.ad_set.all().order_by('id')
        return queryset

    def get_context_data(self, **kwargs):
        """
        Populate 'context' dictionary with the required objects
        """
        context = super(ISDDetailView, self).get_context_data(**kwargs)
        context['object'] = self.isd
        # upload form
        context['upload_form'] = UploadFileForm()
        return context


@require_POST
def add_as(request):
    isd_as = request.POST['inputASname']
    current_isd = request.POST['inputISDname']

    coord_settings = get_object_or_404(OrganisationAdmin,
                                       user_id=request.user.id)

    key = coord_settings.key + "/"
    secret = coord_settings.secret

    base_url = COORD_SERVICE_URI

    insert_as_url = INSERT_AS

    request_url = reduce(urljoin, [base_url, insert_as_url, key, secret])
    headers = {'content-type': 'application/json'}

    try:
        request_id = int(request.POST['inputRequestID'])
        jr = JoinRequest.objects.get(request_id=request_id)

        isd_id, as_id = isd_as.split('-')
        AD.objects.update_or_create(
            as_id=int(as_id),
            isd=ISD.objects.get(id=int(isd_id)),
            is_core_ad=False,
            is_open=False,
            sig_pub_key=jr.sig_pub_key,
            sig_priv_key=jr.sig_priv_key,
            enc_pub_key=jr.enc_pub_key,
            enc_priv_key=jr.enc_priv_key,
            certificate=jr.certificate,
            trc=jr.trc
        )

        try:
            r = requests.post(request_url,
                              json={'isdas': str(isd_as), 'core': False},
                              headers=headers
                              )
        except requests.RequestException:
            print("Failed to create AS at coordination service")

    except (JoinRequest.DoesNotExist, ValueError):
        # no valid JoinRequest with this id, handle manually set id
        if '-' in isd_as:
            _, as_id = isd_as.split('-')
        else:
            as_id = isd_as

        try:
            as_id = int(as_id)
        except ValueError:
            return JsonResponse({'data': 'Invalid AS id'})
        isd = get_object_or_404(ISD, id=int(current_isd))
        # create AS from manually set id
        as_obj = AD.objects.create(as_id=as_id, isd=isd,
                                   is_core_ad=0,
                                   is_open=False)
        as_obj.save()
    as_obj = AD.objects.get(as_id=as_id, isd=current_isd)
    ad_page = reverse('ad_detail', args=[as_obj.id])
    return redirect(ad_page + '#!nodes')


@login_required
def accept_join_request(request, isd_as, request_id):
    coord_settings = get_object_or_404(OrganisationAdmin,
                                       user_id=request.user.id)
    key = coord_settings.key + "/"
    secret = coord_settings.secret

    sig_pub_keys = from_b64(request.POST['sig_pub_key'])
    enc_pub_keys = from_b64(request.POST['enc_pub_key'])
    core_as_id = isd_as
    core_as = AD.objects.get(as_id=isd_as.split('-')[1], isd=isd_as.split('-')[0])
    core_as_sig_priv_key = from_b64(core_as.sig_priv_key)
    core_as_trc = str(core_as.trc)

    certificate = Certificate.from_values(
        request_id, sig_pub_keys, enc_pub_keys, core_as_id,
        core_as_sig_priv_key, INITIAL_CERT_VERSION,
    )

    accept_join_dict = {"isdas": core_as_id,
                        "replies": [
                            {
                                "request_id": int(request_id),
                                "isdas": core_as_id,
                                "certificate": str(certificate),
                                "trc": core_as_trc
                            }
                        ]
                        }
    base_url = COORD_SERVICE_URI
    accept_join_url = UPLOAD_JOIN_REPLIES_SVC
    request_url = reduce(urljoin, [base_url, accept_join_url, key, secret])
    headers = {'content-type': 'application/json'}
    try:
        r = requests.post(request_url, json=accept_join_dict, headers=headers)
        print(r.json())
    except requests.RequestException:
        print("Failed to upload join reply to coordination service")
    current_page = request.META.get('HTTP_REFERER')
    return redirect(current_page)


def accept_join_request_auto(request, request_id):
    coord_settings = get_object_or_404(OrganisationAdmin,
                                       user_id=request.user.id)
    key = coord_settings.key + "/"
    secret = coord_settings.secret

    sig_pub_keys = b'public_signing_key_of_new_as'
    enc_pub_keys = b'public_encryption_key_of_new_as'
    core_as_id = "1-2"
    core_as_sig_priv_key = b'private_signing_key_of_core_as__'

    certificate = Certificate.from_values(
            request_id, sig_pub_keys, enc_pub_keys, core_as_id,
            core_as_sig_priv_key, INITIAL_CERT_VERSION,
        )

    accept_join_dict = {"isdas": core_as_id,
                        "replies": [{
                            "request_id": request_id,
                            "isdas": core_as_id,
                            "certificate": str(certificate),
                            "trc": "trc_123"}]
                        }
    base_url = COORD_SERVICE_URI
    accept_join_url = UPLOAD_JOIN_REPLIES_SVC
    request_url = reduce(urljoin, [base_url, accept_join_url, key, secret])
    headers = {'content-type': 'application/json'}
    try:
        r = requests.post(request_url, json=accept_join_dict, headers=headers)
        answer = r.json()
        print(answer)
    except requests.RequestException:
        print("Failed to upload join reply to coordination service")


@require_POST
@login_required
def new_as_id(request, isd_id):
    response_dict = {'join_replies': [{'request_id': -1, 'isdas': 'Pending'}]}

    coord_settings = get_object_or_404(OrganisationAdmin,
                                       user_id=request.user.id)
    key = coord_settings.key + "/"
    secret = coord_settings.secret

    base_url = COORD_SERVICE_URI

    query_core_ases_url = "/api/as/queryCoreASes/"

    request_url = reduce(urljoin, [base_url, query_core_ases_url, key, secret])
    headers = {'content-type': 'application/json'}
    try:
        r = requests.post(request_url,
                          json={'isd_id': int(isd_id)},
                          headers=headers
                          )
    except requests.ConnectionError:
        # Coordination service is not responding
        response_dict['join_replies'][0]['isdas'] = 'No response'
        return JsonResponse(response_dict)

    answer = r.json()
    core_as_list = answer['coreASes']
    chosen_core_as_index = random.randint(0, len(answer['coreASes'])-1)
    core_as_to_query = core_as_list[chosen_core_as_index]

    join_request_url = UPLOAD_JOIN_REQUEST_SVC

    private_key_sign, public_key_sign = generate_sign_keypair()
    public_key_encr, private_key_encr = generate_enc_keypair()

    join_request_dict = {"isd_to_join": int(isd_id),
                         "as_to_query": core_as_to_query,
                         "sigkey": to_b64(public_key_sign),
                         "enckey": to_b64(public_key_encr)
                         }

    request_url = reduce(urljoin, [base_url, join_request_url, key, secret])
    headers = {'content-type': 'application/json'}
    try:
        r = requests.post(request_url, json=join_request_dict, headers=headers)
        answer = r.json()
        request_id = answer['id']
        print(answer)

        JoinRequest.objects.update_or_create(
            request_id=request_id,
            created_by=request.user,
            join_isd=ISD.objects.get(id=int(isd_id)),
            core_as_signing=core_as_to_query,
            status='SENT',
            sig_pub_key=to_b64(public_key_sign),
            sig_priv_key=to_b64(private_key_sign),
            enc_pub_key=to_b64(public_key_encr),
            enc_priv_key=to_b64(private_key_encr)
        )
    except requests.RequestException:
        print("Failed to make join request at coordination service")

    join_poll_url = POLL_JOIN_REPLIES_SVC
    request_url = reduce(urljoin, [base_url, join_poll_url, key, secret])
    try:
        r = requests.post(request_url, json={}, headers=headers)
    except requests.RequestException:
        print("Failed to poll join replies from coordination service")
        return JsonResponse(response_dict)

    if r.status_code == 200:
        try:
            response = r.json()  # watch out for deserialization vulns
        except json.JSONDecodeError:
            return JsonResponse(response_dict)

        existing_ases = [str(as_elem.isd) + '-' + str(as_elem.as_id)
                         for as_elem in AD.objects.all()]
        response_dict['join_replies'] = []
        for join_reply in response['join_replies']:
            if 'isdas' in join_reply.keys():
                request_id = join_reply['request_id']
                isd_as = join_reply['isdas']
                try:
                    jr = JoinRequest.objects.get(request_id=request_id)
                except JoinRequest.DoesNotExist:
                    # We have a reply for a request we never made
                    print("Unsolicited reply with id: {}".format(request_id))
                    continue
                if jr.status != 'ACCEPTED':
                    jr.status = 'ACCEPTED'
                    jr.certificate = join_reply['certificate']
                    jr.trc = join_reply['trc']
                    jr.save()
                # filter for ASes that have already been created
                if isd_as not in existing_ases:
                    reply_entry = {'isdas': isd_as, 'request_id': request_id}
                    response_dict['join_replies'].append(reply_entry)

    return JsonResponse(response_dict)


class ADDetailView(DetailView):
    model = AD

    def get_context_data(self, **kwargs):
        """
        Populate 'context' dictionary with the required objects
        """
        context = super(ADDetailView, self).get_context_data(**kwargs)
        ad = context['object']

        # Status tab
        context['routers'] = ad.routerweb_set.select_related()
        context['path_servers'] = ad.pathserverweb_set.all()
        context['certificate_servers'] = ad.certificateserverweb_set.all()
        context['beacon_servers'] = ad.beaconserverweb_set.all()
        context['sibra_servers'] = ad.sibraserverweb_set.all()

        context['management_interface_ip'] = get_own_local_ip()
        context['reloaded_topology'] = ad.original_topology
        flat_string = json.dumps(ad.original_topology, sort_keys=True)
        # hash for non cryptographic purpose (state comparison for user warning)
        context['reloaded_topology_hash'] = \
            hashlib.md5(flat_string.encode('utf-8')).hexdigest()
        context['as_id'] = ad.as_id
        context['isd_id'] = ad.isd_id
        isdas = '-'.join([str(ad.isd_id), str(ad.as_id)])
        context['isdas'] = isdas

        # Sort by name numerically
        lists_to_sort = ['routers', 'path_servers',
                         'certificate_servers', 'beacon_servers',
                         'sibra_servers']
        for list_name in lists_to_sort:
            context[list_name] = sorted(
                context[list_name],
                key=lambda el: el.name if el.name is not None else -1
            )

        # Connection requests tab
        context['received_requests'] = {}

        # Join requests: received ISD join requests (only for Core ASes)
        coord_settings = get_object_or_404(OrganisationAdmin,
                                           user_id=self.request.user.id)
        key = coord_settings.key + "/"
        secret = coord_settings.secret

        base_url = COORD_SERVICE_URI
        get_all_requests = POLL_EVENTS_SVC
        request_url = reduce(urljoin, [base_url, get_all_requests, key, secret])
        headers = {'content-type': 'application/json'}
        try:
            r = requests.post(request_url, json={'isdas': isdas},
                              headers=headers)
            if r.status_code == 200:
                answer = r.json()
                context['join_requests'] = answer['join_requests']
                context['received_requests'] = answer['conn_requests']
        except requests.RequestException:
            print("Retrieving requests from coordination service API failed.")

        # Permissions
        context['user_has_perm'] = self.request.user.has_perm('change_ad', ad)
        return context


def as_topo_hash(request, isd_id, as_id):
    try:
        ad = AD.objects.get(as_id=as_id,
                            isd=isd_id)
        flat_string = json.dumps(ad.original_topology, sort_keys=True)
        # hash for non cryptographic purpose (state comparison for user warning)
        topo_hash = hashlib.md5(flat_string.encode('utf-8')).hexdigest()
        return JsonResponse({'topo_hash': topo_hash})
    except AD.DoesNotExist:
        return JsonResponse({'topo_hash': -1})


def _check_user_permissions(request, ad):
    # TODO(rev112) decorator?
    if not request.user.has_perm('change_ad', ad):
        raise PermissionDenied()


@require_POST
def control_process(request, pk, proc_id):
    """
    Send a control command to an AS element instance.
    """
    ad = get_object_or_404(AD, id=pk)  # load by as_id
    _check_user_permissions(request, ad)

    ad_elements = ad.get_all_element_ids()
    if proc_id not in ad_elements:
        return HttpResponseNotFound('Element not found')

    if '_start_process' in request.POST:
        command = 'START'
    elif '_stop_process' in request.POST:
        command = 'STOP'
    else:
        return HttpResponseNotFound('Command not found')

    response = run_remote_command(ad.md_host, proc_id, command,
                                  use_ansible=False)
    if is_success(response):
        return JsonResponse({'status': True})
    else:
        return HttpResponseUnavailable(get_failure_errors(response))


def read_log(request, pk, proc_id):
    # FIXME(rev112): minor duplication, see control_process()
    ad = get_object_or_404(AD, id=pk)  # TODO: query by as_id
    _check_user_permissions(request, ad)

    ad_elements = ad.get_all_element_ids()
    if proc_id not in ad_elements:
        return HttpResponseNotFound('Element not found')
    proc_id = ad.get_full_process_name(proc_id)

    response = run_remote_command(ad.md_host, proc_id, 'STATUS',
                                  use_ansible=False)
    if is_success(response):
        log_data = get_success_data(response)[0]
        if '\n' in log_data:  # Don't show first line of output, why?
            log_data = log_data[log_data.index('\n') + 1:]
        if log_data == '':
            log_data = 'No log output to display, OUT file is empty.'
        return JsonResponse({'data': log_data})
    else:
        return HttpResponseUnavailable(get_failure_errors(response))


@login_required
def accept_connection_request_auto(request, request_id):
    coord_settings = get_object_or_404(OrganisationAdmin,
                                       user_id=request.user.id)
    key = coord_settings.key + "/"
    secret = coord_settings.secret
    replying_as = "1-2"
    requester_isdas = "1-2"
    accept_conn_dict = {"isdas": replying_as,
                        "certificate": "accepting_as_certificate",
                        "replies": [{
                            "request_id": int(request_id),
                            "requester_isdas": requester_isdas,
                            "certificate": "requester_certificate",
                            "ip": "127.0.0.1",
                            "port": 1234,
                            "mtu": 1234,
                            "bandwidth": 1234,
                            }]
                        }
    base_url = COORD_SERVICE_URI
    accept_conn_url = UPLOAD_CONN_REPLIES_SVC
    request_url = reduce(urljoin, [base_url, accept_conn_url, key, secret])
    headers = {'content-type': 'application/json'}
    try:
        r = requests.post(request_url, json=accept_conn_dict, headers=headers)
        answer = r.json()
        print(answer)
    except requests.RequestException:
        print("Uploading connection replies to coordination service API failed.")


class ConnectionRequestView(FormView):
    form_class = ConnectionRequestForm
    template_name = 'ad_manager/new_connection_request.html'
    success_url = ''

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        current_as_id = kwargs['pk']
        form = ConnectionRequestForm(pk=current_as_id)
        context = self.get_context_data(form=form)
        if request.method == 'POST':
            return self.form_valid(form)
        else:
            return self.render_to_response(context)

    def _get_ad(self):
        return get_object_or_404(AD, id=self.kwargs['pk'])

    def form_invalid(self, form):
        print('form is invalid')
        return HttpResponse('Invalid form')

    def form_valid(self, form):
        if not self.request.user.is_authenticated():
            return HttpResponseForbidden('Authentication required')

        posted_data = self.request.POST

        connect_to = posted_data['connect_to']
        connect_from = posted_data['connect_from']
        conn_request = form.instance
        conn_request.connect_to = connect_to
        conn_request.connect_from = get_object_or_404(AD, id=connect_from)
        conn_request.created_by = self.request.user
        conn_request.status = 'SENT'

        conn_request.info = posted_data['info']
        conn_request.router_public_ip = posted_data['router_public_ip']
        conn_request.router_public_port = posted_data['router_public_port']
        conn_request.mtu = posted_data['mtu']
        conn_request.bandwidth = posted_data['bandwidth']
        conn_request.link_type = posted_data['link_type']
        conn_request.save()

        # Talk to SCION coordination service, post connection request
        coord_settings = get_object_or_404(OrganisationAdmin,
                                           user_id=self.request.user.id)
        key = coord_settings.key + "/"
        secret = coord_settings.secret
        isd_as = '-'.join([str(self._get_ad().isd.id),
                           str(self._get_ad().as_id)])

        # Issue with typeflaw attack, and replay when we permit multiple request
        # to be sent in bulk without signing over isdas and request parameters
        # certificate is not included in signature
        connection_request_dict = {"isdas": isd_as, "request":
            {"info": conn_request.info,
             "isdas": connect_to,
             "ip": conn_request.router_public_ip,
             "port": int(conn_request.router_public_port),
             "mtu": int(conn_request.mtu),
             "bandwidth": int(conn_request.bandwidth),
             "linktype": conn_request.link_type,
             "timestamp":
                 iso_timestamp(int(time.time()))},
        "signature": ""}

        # Signature is over the JSON string representation
        # of connection_request_dict
        signing_key = conn_request.connect_from.sig_priv_key
        signed_content = json.dumps(connection_request_dict, sort_keys=True)
        signed_content = bytes(signed_content.encode('utf-8'))
        signature = to_b64(sign(signed_content, from_b64(signing_key)))
        connection_request_dict["signature"] = signature

        connection_request_dict["certificate"] = self._get_ad().certificate
        base_url = COORD_SERVICE_URI
        poll_request_url = UPLOAD_CONN_REQUESTS_SVC
        request_url = reduce(urljoin, [base_url, poll_request_url, key, secret])
        headers = {'content-type': 'application/json'}
        try:
            r = requests.post(request_url,
                              json=connection_request_dict,
                              headers=headers
                              )
            response = r.json()
            print(response)

            # We sent a single request for which we retrieve the request_id
            # assigned by the coordination service
            conn_request.request_id = response['ids'][0]
            conn_request.save()
        except requests.RequestException:
            print("Uploading connection request to coord. service API failed.")

        #  accept_connection_request_auto(self.request, response['ids'][0])

        self.success_url = reverse('sent_requests')
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        context_data['ad'] = self._get_ad()
        return context_data


class NewLinkView(FormView):
    form_class = NewLinkForm
    template_name = 'ad_manager/new_link.html'
    success_url = ''

    def _get_ad(self):
        if not hasattr(self, 'ad'):
            self.ad = get_object_or_404(AD, id=self.kwargs['pk'])  # query as_id
        return self.ad

    def dispatch(self, request, *args, **kwargs):
        ad = self._get_ad()
        _check_user_permissions(request, ad)
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['from_ad'] = self._get_ad()
        return kwargs

    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        context_data['ad'] = self._get_ad()
        return context_data

    def form_valid(self, form):
        this_ad = self._get_ad()
        # from_ad = this_ad
        # to_ad = form.cleaned_data['end_point']
        # link_type = form.cleaned_data['link_type']
        #
        # if link_type == 'PARENT':
        #     from_ad, to_ad = to_ad, from_ad
        #
        # if link_type in ['CHILD', 'PARENT']:
        #     link_type = 'PARENT_CHILD'
        #
        # with transaction.atomic():
        #     link_ads(from_ad, to_ad, link_type)

        self.success_url = reverse('ad_detail', args=[this_ad.id])
        return super().form_valid(form)


def approve_request(ad, ad_request):
    # Create the new AD
    new_id = AD.objects.latest('id').id + 1
    new_ad = AD.objects.create(as_id=new_id, isd=ad.isd,
                               md_host=ad_request.router_public_ip)
    parent_topo_dict = ad.generate_topology_dict()

    with tempfile.TemporaryDirectory() as temp_dir:
        new_topo_dict, parent_topo_dict = create_new_ad_files(parent_topo_dict,
                                                              new_ad.isd.id,
                                                              new_ad.id,
                                                              out_dir=temp_dir)

        # Adjust router ips/ports
        # if ad_request.router_public_ip is None:
        #     ad_request.router_public_ip = ad_request.router_bound_ip

        if ad_request.router_public_port is None:
            ad_request.router_public_port = ad_request.router_bound_port

        _, new_topo_router = find_last_router(new_topo_dict)
        # new_topo_router['Interface']['Addr'] = ad_request.router_bound_ip
        # new_topo_router['Interface']['UdpPort'] = ad_request.router_bound_port

        _, parent_topo_router = find_last_router(parent_topo_dict)
        parent_router_if = parent_topo_router['Interface']
        parent_router_if['ToAddr'] = ad_request.router_public_ip
        parent_router_if['UdpPort'] = ad_request.router_public_port

        new_ad.fill_from_topology(new_topo_dict, clear=True)
        ad.fill_from_topology(parent_topo_dict, clear=True)

        # Update the new topology on disk:
        # Write new config files to disk, regenerate everything else
        # FIXME(rev112): minor duplication, see ad_connect.create_new_ad_files()
        gen = ConfigGenerator(out_dir=temp_dir)
        new_topo_path = gen.path_dict(new_ad.isd.id, new_ad.id)['topo_file_abs']
        write_file(new_topo_path, json.dumps(new_topo_dict,
                                             sort_keys=4, indent=4))
        gen.write_derivatives(new_topo_dict)

        # Resulting package will be stored here
        package_dir = os.path.join('gen', 'AD' + str(
            new_ad))  # os.path.join(PACKAGE_DIR_PATH,
        # 'AD' + str(new_ad)) TODO: replace ad_management functionality
        if os.path.exists(package_dir):
            rmtree(package_dir)
        os.makedirs(package_dir)

        # Prepare package
        # package_name = 'scion_package_AD{}-{}'.format(new_ad.isd, new_ad.id)
        # config_dirs = [os.path.join(temp_dir,x) for x in os.listdir(temp_dir)]
        # ad_request.package_path = prepare_package(out_dir=package_dir,
        #                                           config_paths=config_dirs,
        #                                           package_name=package_name)
        ad_request.new_ad = new_ad
        ad_request.status = 'APPROVED'
        ad_request.save()

        # Give permissions to the user
        request_creator = ad_request.created_by
        assign_perm('change_ad', request_creator, new_ad)

        new_ad.save()
        ad.save()


@login_required
def accept_connection_request(request, request_id, replying_as, posted_data):
    coord_settings = get_object_or_404(OrganisationAdmin,
                                       user_id=request.user.id)
    key = coord_settings.key + "/"
    secret = coord_settings.secret

    # AS requesting the connection and AS accepting the connection should agree
    # on MTU and bandwidth of a link
    negociated_mtu = min(posted_data['accepted_mtu'],
                         posted_data['requested_mtu'])
    negociated_bandwidth = min(posted_data['accepted_bandwidth'],
                               posted_data['requested_bandwidth'])

    accept_conn_dict = {"isdas": str(replying_as),
                        "certificate": str(replying_as.certificate),
                        "replies": [{
                            "request_id": int(request_id),
                            "requester_isdas": posted_data['requester_isdas'],
                            "ip": posted_data['router_public_ip'],
                            "port": int(posted_data['router_public_port']),
                            "mtu": int(negociated_mtu),
                            "bandwidth": int(negociated_bandwidth),
                            }]
                        }
    base_url = COORD_SERVICE_URI
    accept_conn_url = UPLOAD_CONN_REPLIES_SVC
    request_url = reduce(urljoin, [base_url, accept_conn_url, key, secret])
    headers = {'content-type': 'application/json'}
    try:
        r = requests.post(request_url, json=accept_conn_dict, headers=headers)
        print(r.text)
    except requests.RequestException:
        print("Uploading connection replies to coordination service API failed")


@transaction.atomic
@require_POST
def request_action(request, req_id):
    """
    Approve or decline the sent connection request.
    """
    posted_data = request.POST
    replying_isdas = posted_data['replying_isdas']
    isd_id, as_id = replying_isdas.split('-')

    replying_as = get_object_or_404(AD, isd=isd_id, as_id=as_id)
    _check_user_permissions(request, replying_as)

    if '_approve_request' in request.POST:
        accept_connection_request(request, req_id, replying_as, posted_data)
        #  Create/update topology
        return redirect(
            reverse('ad_detail_topology_routers', args=[replying_as.id]))
    elif '_decline_request' in request.POST:
        # Denied request are simply ignored according to the current scion coord
        # implementation
        return redirect(
            reverse('ad_connection_requests', args=[replying_as.id]))

    return HttpResponseNotFound('Action not found')


@login_required
def list_sent_requests(request):
    """
    List requests, sent by the current user.
    """
    user = request.user
    sent_requests = user.connectionrequest_set.all()

    coord_settings = get_object_or_404(OrganisationAdmin,
                                       user_id=request.user.id)
    key = coord_settings.key + "/"
    secret = coord_settings.secret

    received_replies = {}
    if sent_requests:

        requesting_ases = []
        for conn_request in sent_requests:
            requesting_ases.append(conn_request.connect_from)
        requesting_ases = set(requesting_ases)
        requesting_ases.discard(None)

        received_replies = {'replies': []}
        for isd_as in requesting_ases:
            poll_reply_dict = {
                                "isdas": str(isd_as)
                              }
            base_url = COORD_SERVICE_URI
            poll_request_url = POLL_CONN_REPLIES_SVC
            request_url = reduce(urljoin, [base_url, poll_request_url, key, secret])
            headers = {'content-type': 'application/json'}
            try:
                r = requests.post(request_url, json=poll_reply_dict, headers=headers)
                reply = r.json()
                if reply:
                    received_replies['replies'].extend(reply['replies'])
            except requests.RequestException:
                print("Retrieving reply for request issued by AS {} from "
                      "coordination service API failed.".format(isd_as))

    new_received_replies = []
    if 'replies' in received_replies:
        for reply in received_replies['replies']:
            request_id = reply['request_id']
            try:
                conn_request = ConnectionRequest.objects.get(
                    request_id=request_id
                )
                if conn_request.status != 'APPROVED':
                    conn_request.status = 'APPROVED'
                    conn_request.save()
                    new_received_replies.append(conn_request)
                    sent_requests = sent_requests.exclude(request_id=request_id)
            except ConnectionRequest.DoesNotExist:
                # We have a reply for a request we never made
                print("Unsolicited reply with id: {}".format(request_id))
                continue

    return render(request, 'ad_manager/sent_requests.html',
                  {'sent_requests': sent_requests,
                   'received_replies': new_received_replies}
                  )


@permission_required('ad_manager.change_organisationadmin', login_url='/login/')
def coord_service(request):
    """
    Show coordination service related setting to organisation admin
    """
    user = request.user
    form = CoordinationServiceSettingsForm(user_id=user.id)

    return render(request, 'ad_manager/coord_service.html',
                  {'settings_form': form})


@require_POST
@permission_required('ad_manager.change_organisationadmin', login_url='/login/')
def coord_service_update(request):
    current_page = request.META.get('HTTP_REFERER')
    user = request.user
    form = CoordinationServiceSettingsForm(request.POST, user_id=user.id)
    if form.is_valid():
        OrganisationAdmin.\
            objects.update_or_create(key=form.cleaned_data['key'],
                                     secret=form.cleaned_data['secret'],
                                     is_org_admin=True,
                                     user_id=request.user.id)
    return redirect(current_page)


def _get_partial_graph(pov_ad, rank=1):
    partial_graph = {}
    bfs_queue = deque([[pov_ad, rank]])
    while bfs_queue:
        next_ad, ad_rank = bfs_queue.popleft()
        if next_ad in partial_graph:
            continue

        ad_routers = next_ad.routerweb_set.all().select_related('neighbor_ad')
        neighbors = []
        for router in ad_routers:
            neighbor_ad = router.neighbor_ad
            if ad_rank > 0:
                bfs_queue.append([neighbor_ad, ad_rank - 1])
            neighbors.append(neighbor_ad)
        partial_graph[next_ad] = neighbors
    return partial_graph


def _get_node_object(ad):
    node_object = {
        'name': 'AD {}-{}'.format(ad.isd_id, ad.id),
        'group': ad.isd_id,
        'url': ad.get_absolute_url(),
        'networkUrl': reverse('network_view_ad', args=[ad.id]),
        'core': int(ad.is_core_ad),
    }
    return node_object


def network_view_neighbors(request, pk):
    pov_ad = get_object_or_404(AD, id=pk)  # query by as_id
    rank = 2

    partial_graph = _get_partial_graph(pov_ad, rank)
    ad_with_neighbors = partial_graph.keys()

    # Build reverse index
    ad_index_rev = {}
    for i, ad in enumerate(ad_with_neighbors):
        ad_index_rev[ad] = i

    graph = {'nodes': [], 'links': []}
    for ad in ad_with_neighbors:
        index = ad_index_rev[ad]
        neighbors = partial_graph[ad]
        node_object = _get_node_object(ad)
        if ad == pov_ad:
            node_object['pov'] = 1
        graph['nodes'].append(node_object)
        for n in neighbors:
            if n not in ad_index_rev:
                continue
            neighbor_id = ad_index_rev[n]
            if index < neighbor_id:
                graph['links'].append({
                    'source': index,
                    'target': neighbor_id,
                    'value': 1,
                })
    return render(request, 'ad_manager/network_view.html',
                  {'data': graph,
                   'pov_ad': pov_ad})


def network_view(request):
    """
    Prepare network graph visualization.
    """
    all_ads = AD.objects.all().prefetch_related('routerweb_set__neighbor_ad')
    ad_graph_tmp = []
    # Direct and reverse index <-> AS mappings
    ad_index = {}
    ad_index_rev = {}
    for i, ad in enumerate(all_ads):
        ad_index[i] = ad
        ad_index_rev[ad] = i
        ad_routers = ad.routerweb_set.all()
        ad_graph_tmp.append([r.neighbor_ad for r in ad_routers])

    # Build a list of [list of neighbors for every AD]
    ad_graph = []
    for neighbors in ad_graph_tmp:
        ad_graph.append([ad_index_rev[n] for n in neighbors])

    # Translate to D3.js format
    graph = {'nodes': [], 'links': []}
    for index, neighbors in enumerate(ad_graph):
        ad = ad_index[index]
        node_object = _get_node_object(ad)
        graph['nodes'].append(node_object)
        for n in neighbors:
            if index < n:
                graph['links'].append({
                    'source': index,
                    'target': n,
                    'value': 1,
                })
    return render(request, 'ad_manager/network_view.html', {'data': graph})


def wrong_api_call(request):
    print('Wrong API call')
    return JsonResponse({'data': 'Failure'})


static_tmp_path = os.path.join(WEB_ROOT, 'ad_manager', 'static', 'tmp')
yaml_topo_path = os.path.join(static_tmp_path, 'topology.yml')


def st_int(s, default):
    s = s.strip()

    return int(s) if not s == '' else default


def name_entry_dict(name_l, address_l, port_l, addr_int_l, port_int_l):
    ret_dict = {}
    for i in range(len(name_l)):
        if address_l[i] == '':
            continue  # don't include empty entries
        ret_dict[name_l[i]] = {'Addr': address_l[i],
                               'Port': st_int(port_l[i],
                                              SCION_SUGGESTED_PORT),
                               'AddrInternal': addr_int_l[i],
                               'PortInternal': st_int(port_int_l[i], None)
                               }
    return ret_dict


def name_entry_dict_router(tp):
    ret_dict = {}

    name_list = tp.getlist('inputBorderRouterName')
    address_list = tp.getlist('inputBorderRouterAddress')
    port_list = tp.getlist('inputBorderRouterPort')
    interface_list = tp.getlist('inputInterfaceAddr')
    bandwidth_list = tp.getlist('inputInterfaceBandwidth')
    if_id_list = tp.getlist('inputInterfaceIFID')
    remote_name_list = tp.getlist('inputInterfaceRemoteName')
    interface_type_list = tp.getlist('inputInterfaceType')
    link_mtu_list = tp.getlist('inputLinkMTU')
    remote_address_list = tp.getlist('inputInterfaceRemoteAddress')
    remote_port_list = tp.getlist('inputInterfaceRemotePort')
    own_port_list = tp.getlist('inputInterfaceOwnPort')
    for i in range(len(name_list)):
        if address_list[i] == '':
            continue  # don't include empty entries
        ret_dict[name_list[i]] = {'Addr': address_list[i],
                                  'Port': st_int(port_list[i],
                                                 SCION_SUGGESTED_PORT),
                                  'Interface':
                                      {'Addr': interface_list[i],
                                       'Bandwidth': st_int(bandwidth_list[i],
                                                           DEFAULT_BANDWIDTH),
                                       'IFID': st_int(if_id_list[i], 1),
                                       'ISD_AS': remote_name_list[i],
                                       'LinkType': interface_type_list[i],
                                       'MTU': st_int(link_mtu_list[i],
                                                     DEFAULT_MTU),
                                       'ToAddr': remote_address_list[i],
                                       'ToUdpPort':
                                       st_int(remote_port_list[i],
                                              SCION_SUGGESTED_PORT),
                                       'UdpPort': st_int(own_port_list[i],
                                                         SCION_SUGGESTED_PORT)}
                                  }
    return ret_dict


@require_POST
def generate_topology(request):
    topology_params = request.POST.copy()
    topology_params.pop('csrfmiddlewaretoken',
                        None)  # remove csrf entry, as we don't need it here

    mockup_dicts = {}
    tp = topology_params
    isd_as = tp['inputISD_AS']
    isd_id, as_id = isd_as.split('-')
    mockup_dicts['Core'] = True if (tp['inputIsCore'] == 'on') else False

    service_types = ['BeaconServer', 'CertificateServer',
                     'PathServer', 'SibraServer']

    for s_type in service_types:
        section_name = s_type+'s'
        mockup_dicts[section_name] = \
            name_entry_dict(tp.getlist('input{}Name'.format(s_type)),
                            tp.getlist('input{}Address'.format(s_type)),
                            tp.getlist('input{}Port'.format(s_type)),
                            tp.getlist('input{}InternalAddress'.format(s_type)),
                            tp.getlist('input{}InternalPort'.format(s_type)),
                            )

    mockup_dicts['BorderRouters'] = name_entry_dict_router(tp)
    mockup_dicts['ISD_AS'] = tp['inputISD_AS']
    mockup_dicts['MTU'] = st_int(tp['inputMTU'], DEFAULT_MTU)

    # Zookeeper special case
    s_type = 'ZookeeperServer'
    zk_dict = name_entry_dict(tp.getlist('input{}Name'.format(s_type)),
                              tp.getlist('input{}Address'.format(s_type)),
                              tp.getlist('input{}Port'.format(s_type)),
                              tp.getlist(
                                  'input{}InternalAddress'.format(s_type)),
                              tp.getlist('input{}InternalPort'.format(s_type)),
                              )
    named_keys = list(zk_dict.keys())  # copy 'named' keys
    int_key = 1  # dict keys get replaced with numeric keys, 1 based
    for key in named_keys:
        zk_dict[int_key] = zk_dict.pop(key)
        int_key += 1

    mockup_dicts['Zookeepers'] = zk_dict

    # IP:port uniqueness in AS check
    all_ip_port_pairs = []
    for r in ['BeaconServers', 'CertificateServers',
              'PathServers', 'SibraServers', 'Zookeepers']:
        servers_of_type_r = mockup_dicts[r]
        for server in servers_of_type_r:
            curr_pair = servers_of_type_r[server]['Addr'] + ':' + str(
                servers_of_type_r[server]['Port'])
            all_ip_port_pairs.append(curr_pair)
    if len(all_ip_port_pairs) != len(set(all_ip_port_pairs)):
        return JsonResponse(
            {'data': 'IP:port combinations not unique within AS'})

    os.makedirs(static_tmp_path, exist_ok=True)
    with open(yaml_topo_path, 'w') as file:
        yaml.dump(mockup_dicts, file, default_flow_style=False)

    create_local_gen(isd_as, mockup_dicts)
    commit_hash = tp['commitHash']
    # sanitize commit hash from comments, take first part up to |, strip spaces
    commit_hash = (commit_hash.split('|'))[0].strip()
    generate_ansible_hostfile(topology_params,
                              mockup_dicts,
                              isd_as,
                              commit_hash)

    curr_as = get_object_or_404(AD, as_id=as_id, isd=isd_id)
    # load as usual model (for persistance and display in overview)
    # TODO : hash displayed queryset and curr_as query set and compare
    # allow the user to write back the new configuration only if it hasn't
    # changed in the meantime
    curr_as.fill_from_topology(mockup_dicts, clear=True)

    current_page = request.META.get('HTTP_REFERER')
    return redirect(current_page)


def get_own_local_ip():
    result = '127.0.0.1'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('192.168.255.255', 22))
            result = s.getsockname()[0]
    except OSError:
        print('Network is unreachable')
    return result


def add_file_to_tar(new_file, name, tar_file_path):
    with tarfile.open(tar_file_path, 'a') as tar_archive:
        tar_archive.add(new_file, name)
    return


def create_dir_in_tar(new_dir_name, new_dir_path, tar_file_path):
    with tarfile.open(tar_file_path, 'a') as tar_archive:
        new_dir = tarfile.TarInfo(new_dir_name)
        new_dir.type = tarfile.DIRTYPE
        tar_archive.add(new_dir, new_dir_path)
    return


def create_tar_with_file(new_file, name, tar_file_path):
    with tarfile.open(tar_file_path, 'w:') as tar_archive:
        tar_archive.add(new_file, name)
    return


def create_tar(tar_file_path):
    tar_archive = tarfile.open(tar_file_path, 'w:')
    tar_archive.close()
    return


def write_out_inmemory_uploaded(file, destination_file_path):
    # we can not simply copy the InMemoryUploadedFile,
    # we have to read it in chunks to safely get it stored
    with open(destination_file_path, 'wb') as dest:
        for chunk in file.chunks():
            dest.write(chunk)
    return


def create_global_gen(topo_path):
    # ./scion.sh topology -c '/../scion/topology/Switzerland.topo'
    # we reuse the generation facility provided by scion.sh
    scion_sh_path = os.path.join(PROJECT_ROOT, 'scion.sh')
    result = subprocess.check_call([scion_sh_path, 'topology',
                                    '-c', topo_path,
                                    '-o', os.path.join(PROJECT_ROOT,
                                                       'deploy-gen')
                                    ],
                                   cwd=PROJECT_ROOT)
    return result


def handle_uploaded_file(f):
    local_gen_path = os.path.join(WEB_ROOT, 'gen')
    os.makedirs(local_gen_path, exist_ok=True)  # create the folder if not there
    destination_file_path = os.path.join(local_gen_path, f.name)
    write_out_inmemory_uploaded(f, destination_file_path)
    return destination_file_path


@require_POST
def upload_file(request):
    current_page = request.META.get('HTTP_REFERER')
    if request.method == 'GET':
        form = UploadFileForm()
        return render(request, 'isd_list.html', {'form': form})
    elif request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            if '_upload_topo' in request.POST:
                path = handle_uploaded_file(request.FILES['file'])
                create_global_gen(path)  # to get the trc file
            elif '_upload_init_topo' in request.POST:
                path = []
                for topo_file in request.FILES.getlist('file'):
                    path.append(handle_uploaded_file(topo_file))
                reload_data_from_files(path, on_the_fly_refs=True)
        return redirect(current_page)
    else:
        return redirect(current_page)


def lookup_dict_services_prefixes():
    # looks up the prefix used for naming supervisor processes,
    # beacon server -> 'bs', ... TODO: move to util
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
    creates the usual gen folder structure for an ISD/AS under web_scion/gen,
    ready for Ansible deployment
    Args:
        isd_as: isd-as string
        tp: the topology parameter file as a dict of dicts

    """
    # looks up the name of the executable for the service,
    # certificate server -> 'cert_server', ...
    lkx = lookup_dict_executables()

    isd_id, as_id = isd_as.split('-')

    local_gen_path = os.path.join(WEB_ROOT, 'gen')

    # Add the dispatcher folder in sub/web/gen/ if not already there
    dispatcher_folder_path = os.path.join(local_gen_path, 'dispatcher')
    if not os.path.exists(dispatcher_folder_path):
        copytree(os.path.join(PROJECT_ROOT, 'deploy-gen', 'dispatcher'),
                 dispatcher_folder_path)

    # TODO: Cert distribution needs integration with scion-coord,
    # using bruteforce copying over some gen certs and
    # matching keys to get Ansible testing
    # before integration with scion-coord
    shared_files_path = os.path.join(local_gen_path, 'shared_files')

    rmtree(os.path.join(shared_files_path), True)  # rm shared_files & content
    # populate the shared_files folder with the relevant files for this AS
    certgen_path = os.path.join(PROJECT_ROOT,
                                'deploy-gen/ISD{}/AS{}/endhost/'.format(isd_id,
                                                                        as_id))
    copytree(certgen_path, shared_files_path)
    # remove files that are not shared
    try:
        os.remove(os.path.join(shared_files_path, 'supervisord.conf'))
    except OSError:
        pass
    try:
        os.remove(os.path.join(shared_files_path, 'topology.yml'))
    except OSError:
        pass
    try:
        as_path = 'ISD{}/AS{}/'.format(isd_id, as_id)
        as_path = os.path.join(local_gen_path, as_path)
        rmtree(as_path, True)
    except OSError:
        pass

    types = ['beacon_server', 'certificate_server', 'router', 'path_server',
             'sibra_server', 'zookeeper_service']  # 'domain_server', # tmp fix
    # until the discovery replaces it

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
        for serv_name in replicas:
            config = configparser.ConfigParser()
            # replace serv_name if zookeeper special case (they have only ids)
            if service_type == 'zookeeper_service':
                serv_name = '{}{}-{}-{}'.format('zk', isd_id,
                                                as_id, zk_name_counter)
                zk_name_counter += 1
            config['program:' + serv_name] = \
                {'startsecs': '5',
                 'command': '"bin/{0}" "{1}" "gen/ISD{2}/AS{3}/{1}"'.format(
                     executable_name, serv_name, isd_id, as_id),
                 'startretries': '0',
                 'stdout_logfile': 'logs/' + str(serv_name) + '.OUT',
                 'redirect_stderr': 'true',
                 'autorestart': 'false',
                 'environment': 'PYTHONPATH=.',
                 'autostart': 'false',
                 'stdout_logfile_maxbytes': '0'}

            # replace command entry if zookeeper special case
            if service_type == 'zookeeper_service':
                zk_config_path = os.path.join(PROJECT_ROOT,
                                              'topology',
                                              'Zookeeper.yml')
                zk_config = {}
                with open(zk_config_path, 'r') as stream:
                    try:
                        zk_config = yaml.load(stream)
                    except (yaml.YAMLError, KeyError):
                        zk_config = ''  # TODO: give user feedback, add TC
                class_path = zk_config['Environment']['CLASSPATH']
                zoomain_env = zk_config['Environment']['ZOOMAIN']
                command_string = '"java" "-cp" ' \
                                 '"gen/{1}/{2}/{0}:{3}" ' \
                                 '"-Dzookeeper.' \
                                 'log.file=logs/{0}.log" ' \
                                 '"{4}" ' \
                                 '"gen/ISD{1}/AS{2}/{0}/' \
                                 'zoo.cfg"'.format(serv_name,
                                                   isd_id,
                                                   as_id,
                                                   class_path,
                                                   zoomain_env)
                config['program:' + serv_name]['command'] = command_string

            node_path = 'ISD{}/AS{}/{}'.format(isd_id, as_id, serv_name)
            node_path = os.path.join(local_gen_path, node_path)
            # os.makedirs(node_path, exist_ok=True)
            if not os.path.exists(node_path):
                copytree(os.path.join(shared_files_path), node_path)
            conf_file_path = os.path.join(node_path, 'supervisord.conf')
            with open(conf_file_path, 'w') as configfile:
                config.write(configfile)

            # copy AS topology.yml file into node
            one_of_topology_path = os.path.join(node_path, 'topology.yml')
            one_of_topology = particular_topo_instance(tp, type_key)
            with open(one_of_topology_path, 'w') as file:
                yaml.dump(one_of_topology, file, default_flow_style=False)
            # copy(yaml_topo_path, node_path)  # Do not share global topology
            # as each node get its own topology file

            # create zlog file
            tmpl = Template(read_file(os.path.join(PROJECT_ROOT,
                                                   "topology/zlog.tmpl")))
            cfg = os.path.join(node_path, "%s.zlog.conf" % serv_name)
            write_file(cfg, tmpl.substitute(name=service_type, elem=serv_name))

            # Generating only the needed intermediate parts
            # not used as for now we generator.py all certs and keys resources

    # Add endhost folder for all ASes
    node_path = 'ISD{}/AS{}/{}'.format(isd_id, as_id, 'endhost')
    node_path = os.path.join(local_gen_path, node_path)
    if not os.path.exists(node_path):
        copytree(os.path.join(shared_files_path), node_path)
    copy(yaml_topo_path, node_path)


def particular_topo_instance(tp, type_key):
    #  Little trow away logic handling the NATed case until topo represents
    # internal and external addresses

    singular_topo = deepcopy(tp)

    for server_type in singular_topo.keys():  # services know only internal
        if server_type.endswith("Servers") or server_type == 'Zookeepers':
            for entry in singular_topo[server_type]:
                internal_address = singular_topo[server_type][entry].pop(
                    'AddrInternal')
                internal_port = singular_topo[server_type][entry].pop(
                    'PortInternal')
                if type_key == 'BorderRouters':
                    continue  # Border routers only know about external
                if internal_address != '':
                    singular_topo[server_type][entry]['Addr'] = internal_address
                if internal_port is not None:
                    singular_topo[server_type][entry]['Port'] = internal_port
    return singular_topo


def run_remote_command(ip, process_name, command, use_ansible=True):

    if not use_ansible:
        server = xmlrpc.client.ServerProxy('http://{}:9011'.format(ip))
        wait_for_result = True
        result = False
        if command == 'retrieve_tar':
            result = server.supervisor.startProcess(process_name,
                                                    wait_for_result)

        if command == 'STOP':
            result = server.supervisor.stopProcess(process_name,
                                                   wait_for_result)
        if command == 'START':
            result = server.supervisor.startProcess(process_name,
                                                    wait_for_result)
        if command == 'STATUS':
            offset = 0
            length = 4000
            result = server.supervisor.tailProcessStdoutLog(process_name,
                                                            offset, length)
        print('Remote operation {} completed: {}'.format(command, result))
    else:
        # using the ansibleCLI instead of
        # duplicating code to use the PlaybookExecutor
        result = "Call failed"
        try:
            result = subprocess.check_call(['ansible-playbook',
                                            os.path.join(PROJECT_ROOT,
                                                         'ansible',
                                                         'deploy-current.yml')],
                                           cwd=PROJECT_ROOT)
        except subprocess.CalledProcessError:
            print(result)
    return result


def run_rpc_command(ip, uuid, management_interface_ip, command, isd_id, as_id):
    server = xmlrpc.client.ServerProxy('http://{}:9012'.format(ip))
    result = None
    if command == 'register':
        result = server.register(management_interface_ip, isd_id, as_id)
    elif command == 'retrieve_tar':
        result = server.retrieve_configuration(uuid, management_interface_ip,
                                               isd_id, as_id)
    else:
        print('Wrong command')
    print('Remote operation {} completed: {}'.format(command, 'True'))
    return result
