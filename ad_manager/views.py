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
import hashlib
import json
import logging
import os
import posixpath
import requests
import socket
import subprocess
import tarfile
import yaml
from collections import deque
from copy import deepcopy
from shutil import (
    copy,
    copytree,
    rmtree,
)
from string import Template
from urllib.parse import urljoin

# External packages
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import (
    HttpResponse,
    HttpResponseForbidden,
    JsonResponse,
)
from django.shortcuts import redirect, get_object_or_404, render
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_POST
from django.views.generic import ListView, DetailView, FormView

# SCION
from lib.util import (
    read_file,
    write_file,
)
from lib.crypto.certificate import Certificate
from lib.crypto.asymcrypto import (
    generate_sign_keypair,
    generate_enc_keypair,
)
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    PATH_SERVICE,
    ROUTER_SERVICE,
    SIBRA_SERVICE,
)
from lib.defines import DEFAULT_MTU
from lib.defines import GEN_PATH, PROJECT_ROOT
from lib.packet.scion_addr import ISD_AS
from scripts.reload_data import reload_data_from_files

# SCION-WEB
from ad_manager.forms import (
    ConnectionRequestForm,
    CoordinationServiceSettingsForm,
    UploadFileForm,
)
from ad_manager.models import (
    AD,
    ISD,
    JoinRequest,
    OrganisationAdmin,
)
from ad_manager.util.hostfile_generator import generate_ansible_hostfile
from ad_manager.util.util import to_b64, from_b64
from ad_manager.util.defines import (
    COORD_SERVICE_URI,
    DEFAULT_BANDWIDTH,
    INITIAL_CERT_VERSION,
    POLL_JOIN_REPLY_SVC,
    POLL_EVENTS_SVC,
    SCION_SUGGESTED_PORT,
    UPLOAD_JOIN_REQUEST_SVC,
    UPLOAD_JOIN_REPLY_SVC,
)


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

REQ_SENT = 'SENT'
REQ_APPROVED = 'APPROVED'
logger = logging.getLogger("scion-web")


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
        queryset = isd.ad_set.all().order_by('as_id')
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
@login_required
def poll_join_reply(web_req):
    logger.info("Polling Join Reply")
    current_page = web_req.META.get('HTTP_REFERER')
    try:
        coord = OrganisationAdmin.objects.get(user_id=web_req.user.id)
    except OrganisationAdmin.DoesNotExist:
        logger.error("Retrieving key and secret failed.")
        return redirect(current_page)

    open_join_requests = JoinRequest.objects.filter(status=REQ_SENT)
    for req in open_join_requests:
        jr_id = req.request_id
        logger.info('Pending request = %s', jr_id)
        request_url = urljoin(COORD_SERVICE_URI, posixpath.join(
                              POLL_JOIN_REPLY_SVC, coord.key, coord.secret))
        logger.info('url = %s' % request_url)
        headers = {'content-type': 'application/json'}
        try:
            r = requests.post(request_url, json={'request_id': jr_id},
                              headers=headers)
        except requests.RequestException:
            logger.info("Retrieving requests from scion-coord failed.")

        if r.status_code == 200:
            handle_join_reply(r, web_req, jr_id)
        else:
            logger.error("Poll Join Reply for request %s return with code %s",
                         jr_id, r.status_code)

    return redirect(current_page)


def handle_join_reply(reply, web_req, jr_id):
    logger.info("resp = %s", reply.json())
    join_reply = reply.json()

    new_as = ISD_AS(join_reply['assigned_isdas'])

    # TODO(ercanucan): create the ISD in DB if it's not yet in DB
    AD.objects.update_or_create(
        as_id=int(new_as[1]),
        isd=ISD.objects.get(id=int(new_as[0])),
        is_core_ad=False,
        is_open=False,
        certificate=join_reply['certificate'],
        trc=join_reply['trc']
    )
    messages.success(web_req, 'Created new AS with ID %s.' % new_as)

    # change join request status to APPROVED
    JoinRequest.objects.filter(request_id=jr_id).update(status=REQ_APPROVED)


@login_required
def accept_join_request(request, isd_as, request_id):
    """
    Accepts the join request, assigns a new AS ID to
    the requesting party and creates the certificate.
    This function is only executed by a core AS.
    """
    current_page = request.META.get('HTTP_REFERER')
    coord = get_object_or_404(OrganisationAdmin, user_id=request.user.id)
    logger.info("new AS name = %s isd_as = %s", request.POST['newASname'],
                isd_as)

    joining_as = request.POST['newASname']
    sig_pub_key = from_b64(request.POST['sig_pub_key'])
    enc_pub_key = from_b64(request.POST['enc_pub_key'])
    own_isdas = ISD_AS(isd_as)
    signing_as = AD.objects.get(as_id=own_isdas[1],
                                isd=own_isdas[0])
    signing_as_sig_priv_key = from_b64(signing_as.sig_priv_key)
    signing_as_trc = str(signing_as.trc)
    joining_isdas = ISD_AS.from_values(own_isdas[0], joining_as)

    certificate = Certificate.from_values(
        str(joining_isdas), sig_pub_key, enc_pub_key, str(own_isdas),
        signing_as_sig_priv_key, INITIAL_CERT_VERSION,
    )

    accept_join_dict = {"isdas": str(own_isdas),
                        "join_reply":
                            {
                                "request_id": int(request_id),
                                "joining_isdas": str(joining_isdas),
                                "signing_isdas": str(own_isdas),
                                "certificate": str(certificate),
                                "trc": signing_as_trc
                            }
                        }
    logger.info("accept join dict = %s", accept_join_dict)
    request_url = urljoin(COORD_SERVICE_URI, posixpath.join(
                          UPLOAD_JOIN_REPLY_SVC, coord.key, coord.secret))
    headers = {'content-type': 'application/json'}
    try:
        requests.post(request_url, json=accept_join_dict, headers=headers)
    except requests.RequestException:
        logger.error("Failed to upload join reply to coordination service")
    return redirect(current_page)


@require_POST
@login_required
def request_new_as_id(request):
    current_page = request.META.get('HTTP_REFERER')
    # check the validity of parameters
    if not request.POST["inputISDtojoin"].isdigit():
        messages.error(request, 'ISD to join has to be a number!')
        return redirect(current_page)

    isd_to_join = int(request.POST["inputISDtojoin"])

    # get the key and secret necessary to query SCION-coord
    coord = get_object_or_404(OrganisationAdmin, user_id=request.user.id)

    # generate the sign and encryption keys
    private_key_sign, public_key_sign = generate_sign_keypair()
    public_key_encr, private_key_encr = generate_enc_keypair()

    join_request_dict = {"isd_to_join": isd_to_join,
                         "sigkey": to_b64(public_key_sign),
                         "enckey": to_b64(public_key_encr)
                         }

    request_url = urljoin(COORD_SERVICE_URI, posixpath.join(
                          UPLOAD_JOIN_REQUEST_SVC, coord.key, coord.secret))
    headers = {'content-type': 'application/json'}

    logger.info("Request = %s\nJoin Request Dict = %s", request_url,
                join_request_dict)
    try:
        r = requests.post(request_url, json=join_request_dict, headers=headers)
    except requests.RequestException:
        messages.error(request,
                       'Failed to submit ISD join request at scion-coord!')
        return redirect(current_page)

    if r.status_code != 200:
        messages.error(request, 'Submitting join request '
                                'failed with code %s!' % r.status_code)
        return redirect(current_page)

    resp = r.json()
    request_id = resp['id']
    logger.info("request_id = %s", request_id)
    JoinRequest.objects.update_or_create(
        request_id=request_id,
        created_by=request.user,
        isd_to_join=isd_to_join,
        status=REQ_SENT,
        sig_pub_key=to_b64(public_key_sign),
        sig_priv_key=to_b64(private_key_sign),
        enc_pub_key=to_b64(public_key_encr),
        enc_priv_key=to_b64(private_key_encr)
    )

    messages.success(request, 'Join Request Submitted Successfully.'
                              ' Request ID = %s' % request_id)
    return redirect(current_page)


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
        return get_object_or_404(AD, as_id=self.kwargs['pk'])

    def form_invalid(self, form):
        logger.error('Connection request form is invalid')
        return HttpResponse('Invalid form')

    def form_valid(self, form):
        if not self.request.user.is_authenticated():
            return HttpResponseForbidden('Authentication required')

        logger.info("Submitting Connection Request not yet implemented.")
        self.success_url = self._get_ad().get_absolute_url()
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        context_data['ad'] = self._get_ad()
        return context_data


class ADDetailView(DetailView):
    model = AD

    def get_object(self):
        return get_object_or_404(AD, as_id=self.kwargs['as_id'])

    def get_context_data(self, **kwargs):
        """
        Populate 'context' dictionary with the required objects
        """
        context = super().get_context_data(**kwargs)
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
        context['isdas'] = str(ISD_AS.from_values(ad.isd_id, ad.as_id))

        # Sort by name numerically
        lists_to_sort = ['routers', 'path_servers',
                         'certificate_servers', 'beacon_servers',
                         'sibra_servers']
        for list_name in lists_to_sort:
            context[list_name] = sorted(
                context[list_name],
                key=lambda el: el.name if el.name is not None else -1
            )

        # Permissions
        context['user_has_perm'] = self.request.user.has_perm('change_ad', ad)
        # Connection requests tab
        context['join_requests'] = {}
        context['received_requests'] = {}

        try:
            coord = OrganisationAdmin.objects.get(user_id=self.request.user.id)
        except OrganisationAdmin.DoesNotExist:
            logger.error("Retrieving key and secret failed!!.")
            return context

        request_url = urljoin(COORD_SERVICE_URI, posixpath.join(
                              POLL_EVENTS_SVC, coord.key, coord.secret))
        headers = {'content-type': 'application/json'}
        try:
            r = requests.post(request_url, json={'isdas': context['isdas']},
                              headers=headers)
            if r.status_code == 200:
                answer = r.json()
                context['join_requests'] = answer['join_requests']
                context['received_requests'] = answer['conn_requests']
                logger.info("join requests = %s", context['join_requests'])
                logger.info("conn requests = %s", context['received_requests'])
        except requests.RequestException:
            logger.info("Retrieving requests from scion-coord failed.")

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
        OrganisationAdmin.objects.update_or_create(
            key=form.cleaned_data['key'],
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
    pov_ad = get_object_or_404(AD, id=pk)  # TODO(ercanucan): query by as_id
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
    logger.error('Wrong API call')
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
        logger.error('Network is unreachable')
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
