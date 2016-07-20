# Stdlib
import base64
import json
import random
import requests
import tempfile
import time
import os
import hashlib
from collections import deque
from shutil import rmtree
from time import sleep
from urllib.parse import urljoin

# External packages
import dictdiffer
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
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
from django.views.decorators.csrf import csrf_exempt

from datetime import datetime
import yaml
import tarfile
import configparser
import xmlrpc.client
import socket

# SCION
from guardian.shortcuts import assign_perm
from ad_manager.util.response_handling import (
    get_failure_errors,
    get_success_data,
    is_success,
    response_failure,
)
from ad_manager.forms import (
    ConnectionRequestForm,
    NewLinkForm,
    PackageVersionSelectForm,
    UploadFileForm
)
from ad_manager.models import AD, ISD, PackageVersion, ConnectionRequest, Node
from ad_manager.util import management_client
from ad_manager.util.ad_connect import (
    create_new_ad_files,
    find_last_router,
    # link_ads,
)
from ad_manager.util.errors import HttpResponseUnavailable
from lib.util import (get_cert_chain_file_path,
                      get_trc_file_path,
                      get_sig_key_file_path,
                      get_enc_key_file_path,
                      write_file)
from topology.generator import (COMMON_DIR,
                                ConfigGenerator,
                                DEFAULT_PATH_POLICY_FILE,)
# DEFAULT_ZK_CONFIG

from lib.crypto.asymcrypto import generate_sign_keypair
from lib.crypto.certificate import Certificate, CertificateChain
from lib.defines import (BEACON_SERVICE,
                         CERTIFICATE_SERVICE,
                         DNS_SERVICE,
                         PATH_SERVICE,
                         ROUTER_SERVICE,
                         SIBRA_SERVICE)
from lib.defines import (  # SCION_UDP_PORT,
                         SCION_UDP_EH_DATA_PORT,
                         # SCION_DNS_PORT,
                         SCION_ROUTER_PORT,
                         DEFAULT_MTU,
                         # SCION_MIN_MTU
                         )
from lib.defines import GEN_PATH, PROJECT_ROOT

from ad_manager.util.hostfile_generator import generate_ansible_hostfile

import subprocess
from shutil import copy, copytree

DEFAULT_BANDWIDTH = 1000

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
# Scion domain name server
DNS_EXECUTABLE = "dns_server"
# Scion edge router
ROUTER_EXECUTABLE = "router"
# Zookeeper executable
ZOOKEEPER_EXECUTABLE = "zookeeper.jar"

#: All the service types executables
#  TODO: make PR to add into lib.defines as it used to
SERVICE_EXECUTABLES = (
    BEACON_EXECUTABLE,
    CERTIFICATE_EXECUTABLE,
    DNS_EXECUTABLE,
    PATH_EXECUTABLE,
    ROUTER_EXECUTABLE,
    SIBRA_EXECUTABLE,
)

SERVICE_NICKNAMES = ["er", "ps", "bs", "cs", "sb"]

login_key = settings.LOGIN_KEY
login_secret = settings.LOGIN_SECRET


class ISDListView(ListView):
    model = ISD
    paginate_by = 8


@require_POST
def add_isd(request):
    new_isd_id = request.POST['inputISDname']
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
    # Obtain the ISD for which the request is being made
    current_isd = request.POST['inputISDname']
    isd = get_object_or_404(ISD, id=int(current_isd))

    # Generate the signature and encryption keys for the new AS
    sig_pub, sig_priv = generate_sign_keypair()
    enc_pub, enc_priv = generate_sign_keypair()
    sig_pub = base64.b64encode(sig_pub).decode('utf-8')
    sig_priv = base64.b64encode(sig_priv).decode('utf-8')
    enc_pub = base64.b64encode(enc_pub).decode('utf-8')
    enc_priv = base64.b64encode(enc_priv).decode('utf-8')

    # Send a POST request to scion-coord for registering a new AS
    url = urljoin(settings.SCION_COORD_BASE_URL,
                  settings.UPLOAD_JOIN_REQUEST_SVC)
    url += "/" + login_key + "/" + login_secret
    params ={
                'isd_to_join': int(current_isd),
                'sigkey': sig_pub,
                'enckey': enc_pub,
            }
    headers = {'content-type': 'application/json'}
    r = requests.post(url, json=params, headers=headers)
    if r.status_code != 200 :  # Debug
        return HttpResponse("Failed to add a new as")

    # Obtain the request ID from the scion-coord and keep looking for a response
    # to the join request against that request ID
    request_id = json.loads(r.text)['id']
    url = urljoin(settings.SCION_COORD_BASE_URL, settings.POLL_JOIN_REPLY_SVC)
    url += "/" + login_key + "/" + login_secret
    params ={
                "request_id": request_id
            }
    while True:
        r = requests.post(url, json=params, headers=headers)
        if r.status_code == 200 and r.text != "No reply\n":
            break
        sleep(2)

    # Insert new AS entry into the database, using the isd_as in the response
    as_info = json.loads(r.text)
    isd_id, new_as_id = as_info['isdas'].split('-')
    as_obj = AD.objects.create(id=new_as_id,
                               isd=isd,
                               is_core_ad=0,
                               dns_domain='',
                               is_open=False,
                               sig_pub_key=sig_pub,
                               sig_priv_key=sig_priv,
                               enc_pub_key=enc_pub,
                               enc_priv_key=enc_priv,
                               certificate=as_info['certificate']
                               cert_version=as_info['cert_version'])
    as_obj.save()

    # Create the directory structure in 'gen' for the new AS.
    # This overwrites the existing (if present) directory of the AS
    create_local_gen_without_topo(as_info, sig_priv, enc_priv)

    ad_page = reverse('ad_detail', args=[new_as_id])
    return redirect(ad_page + '#!nodes')


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
        context['dns_servers'] = ad.dnsserverweb_set.all()
        context['sibra_servers'] = ad.sibraserverweb_set.all()

        context['nodes'] = Node.objects.all()
        context['management_interface_ip'] = get_own_local_ip()
        context['reloaded_topology'] = ad.original_topology
        flat_string = json.dumps(ad.original_topology, sort_keys=True)
        # hash for non cryptographic purpose (state comparison for user warning)
        context['reloaded_topology_hash'] = \
            hashlib.md5(flat_string.encode('utf-8')).hexdigest()
        context['as_id'] = ad.id
        context['isd_id'] = ad.isd_id

        # Sort by name numerically
        lists_to_sort = ['routers', 'path_servers',
                         'certificate_servers', 'beacon_servers',
                         'dns_servers', 'sibra_servers']
        for list_name in lists_to_sort:
            context[list_name] = sorted(
                context[list_name],
                key=lambda el: el.name if el.name is not None else -1
            )

        # Update tab
        context['choose_version_form'] = PackageVersionSelectForm()

        # Connection requests tab
        context['received_requests'] = ad.received_requests.all()

        # Permissions
        context['user_has_perm'] = self.request.user.has_perm('change_ad', ad)
        return context


def get_ad_status(request, pk):
    """
    Send a query to the corresponding management daemon, asking for the status
    of AS servers.
    """
    ad = get_object_or_404(AD, id=pk)
    ad_info_list_response = ad.query_ad_status()
    if is_success(ad_info_list_response):
        return JsonResponse({'data': get_success_data(ad_info_list_response)})
    else:
        error = get_failure_errors(ad_info_list_response)
        return HttpResponseUnavailable(error)


@csrf_exempt  # remove csrf for this request
def as_topo_hash(request, isd_id, as_id):
    try:
        ad = AD.objects.get(id=as_id,
                            isd=isd_id)
        flat_string = json.dumps(ad.original_topology, sort_keys=True)
        # hash for non cryptographic purpose (state comparison for user warning)
        topo_hash = hashlib.md5(flat_string.encode('utf-8')).hexdigest()
        return JsonResponse({'topo_hash': topo_hash})
    except AD.DoesNotExist:
        return JsonResponse({'topo_hash': -1})


def get_group_master(request, pk):
    """
    Get the server group master (the one, who holds the lock in ZK).
    """
    ad = get_object_or_404(AD, id=pk)
    server_type = request.GET.get('server_type', '')
    fetch_server_types = [BEACON_SERVICE, DNS_SERVICE]
    if server_type not in fetch_server_types:
        return HttpResponseNotFound('Invalid server type')

    response = management_client.get_master_id(ad.md_host, ad.isd.id, ad.id,
                                               server_type)
    if is_success(response):
        master_id = get_success_data(response)
        return JsonResponse({'server_type': server_type,
                             'server_id': master_id})
    else:
        return HttpResponseUnavailable(get_failure_errors(response))


def _get_changes(current_topology, remote_topology):
    current_topology = copy.deepcopy(current_topology)
    remote_topology = copy.deepcopy(remote_topology)

    exclude_key_list = ['Zookeepers']
    for exclude_key in exclude_key_list:
        current_topology.pop(exclude_key, None)
        remote_topology.pop(exclude_key, None)

    diff_changes = list(dictdiffer.diff(current_topology, remote_topology))
    processed_changes = []
    for change in diff_changes:
        change_type, element, changes = list(change)
        change = 'Local -> remote: {}, element: {}, changes: {}'.format(
            change_type, str(element), str(changes)
        )
        processed_changes.append(change)
    return processed_changes


def compare_remote_topology(request, pk):
    """
    Retrieve the remote topology and compare it with the one stored in the
    database.
    """
    ad = get_object_or_404(AD, id=pk)
    remote_topology = ad.get_remote_topology()
    if not remote_topology:
        return HttpResponseUnavailable('Cannot get the topology')

    current_topology = ad.generate_topology_dict()

    changes = _get_changes(current_topology, remote_topology)
    if changes:
        state = 'CHANGED'
    else:
        state = 'OK'
    return JsonResponse({'state': state, 'changes': changes})


@require_POST
@transaction.atomic
def update_topology(request, pk):
    """
    Update topology action: either push or pull the topology.
    """
    ad = get_object_or_404(AD, id=pk)
    _check_user_permissions(request, ad)

    ad_page = reverse('ad_detail', args=[ad.id])
    if '_pull_topology' in request.POST:
        return _update_from_remote_topology(request, ad)
    elif '_push_topology' in request.POST:
        return _push_local_topology(request, ad)
    return redirect(ad_page)


def _push_local_topology(request, ad):
    local_topo = ad.generate_topology_dict()
    # TODO move to model?
    response = management_client.push_topology(ad.md_host, str(ad.isd.id),
                                               str(ad.id), local_topo)
    topology_tag = 'topology'
    if is_success(response):
        messages.success(request, 'OK', extra_tags=topology_tag)
    else:
        messages.error(request, get_failure_errors(response),
                       extra_tags=topology_tag)
    # Wait until supervisor is restarting
    time.sleep(1)
    return redirect(reverse('ad_detail_topology', args=[ad.id]))


def _update_from_remote_topology(request, ad):
    """
    Atomically retrieve the remote topology and update the stored topology
    for the given AD.
    """
    remote_topology_dict = ad.get_remote_topology()
    ad.fill_from_topology(remote_topology_dict, clear=True)
    return redirect(reverse('ad_detail_topology', args=[ad.id]))


def _send_update(request, ad, package):
    """
    Send the update package and initiate the update process.
    """
    # TODO move to model?
    if package.exists():
        result = management_client.send_update(ad.md_host, ad.isd_id, ad.id,
                                               package.filepath)
    else:
        result = response_failure('Package not found')

    update_tag = 'updates'
    if is_success(result):
        messages.success(request, 'Update started', extra_tags=update_tag)
    else:
        error = get_failure_errors(result)
        messages.error(request, error, extra_tags=update_tag)
    return redirect(reverse('ad_detail_updates', args=[ad.id]))


def _download_update(request, package):
    """
    Download the update package straight from the web panel.
    """
    if not package.exists():
        return HttpResponseNotFound('Package not found')
    return _download_file_response(package.filepath)


@require_POST
def software_update_action(request, pk):
    ad = get_object_or_404(AD, id=pk)
    _check_user_permissions(request, ad)

    ad_page = reverse('ad_detail', args=[ad.id])
    form = PackageVersionSelectForm(request.POST)
    if form.is_valid():
        package = form.cleaned_data['selected_version']
        if '_download_update' in request.POST:
            return _download_update(request, package)
        elif '_install_update' in request.POST:
            return _send_update(request, ad, package)
    return redirect(ad_page)


@require_POST
def refresh_versions(request, pk):
    """
    Refresh version choice form element.
    """
    ad = get_object_or_404(AD, id=pk)
    PackageVersion.discover_packages()
    updates_page = reverse('ad_detail_updates', args=[ad.id])
    return redirect(updates_page)


def _download_file_response(file_path, file_name=None, content_type=None):
    if file_name is None:
        file_name = os.path.basename(file_path)
    if content_type is None:
        content_type = 'application/x-gzip'
    with open(file_path, 'rb') as file_fh:
        response = HttpResponse(file_fh.read(), content_type=content_type)
        response['Content-Length'] = file_fh.tell()
    response['Content-Disposition'] = ('attachment; '
                                       'filename={}'.format(file_name))
    return response


def _connect_new_ad(request, ad):
    # TODO(rev112): Remove or move to approve_request()
    topology_page = reverse('ad_detail_topology', args=[ad.id])

    # Chech that remote topology exists
    remote_topology = ad.get_remote_topology()
    topology_tag = 'topology'
    if not remote_topology:
        messages.error(request, 'Cannot get the remote topology',
                       extra_tags=topology_tag)
        return redirect(topology_page)

    # Find if there are differences
    local_topology = ad.generate_topology_dict()
    if _get_changes(local_topology, remote_topology):
        messages.error(request, 'Topologies are inconsistent, '
                                'please push or pull the topology',
                       extra_tags=topology_tag)
        return redirect(topology_page)


def _check_user_permissions(request, ad):
    # TODO(rev112) decorator?
    if not request.user.has_perm('change_ad', ad):
        raise PermissionDenied()


@require_POST
def control_process(request, pk, proc_id):
    """
    Send a control command to an AS element instance.
    """
    ad = get_object_or_404(AD, id=pk)
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

    response = management_client.control_process(ad.md_host, ad.isd.id, ad.id,
                                                 proc_id, command)
    if is_success(response):
        return JsonResponse({'status': True})
    else:
        return HttpResponseUnavailable(get_failure_errors(response))


def read_log(request, pk, proc_id):
    # FIXME(rev112): minor duplication, see control_process()
    ad = get_object_or_404(AD, id=pk)
    _check_user_permissions(request, ad)

    ad_elements = ad.get_all_element_ids()
    if proc_id not in ad_elements:
        return HttpResponseNotFound('Element not found')
    proc_id = ad.get_full_process_name(proc_id)

    response = management_client.read_log(ad.md_host, proc_id)
    if is_success(response):
        log_data = get_success_data(response)[0]
        if '\n' in log_data:  # Don't show first line of output, why?
            log_data = log_data[log_data.index('\n') + 1:]
        if log_data == '':
            log_data = 'No log output to display, OUT file is empty.'
        return JsonResponse({'data': log_data})
    else:
        return HttpResponseUnavailable(get_failure_errors(response))


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

        connect_to = self._get_ad()
        con_request = form.instance
        con_request.connect_to = connect_to
        con_request.created_by = self.request.user
        con_request.status = 'SENT'

        posted_data = self.request.POST

        con_request.info = posted_data['info']
        con_request.router_public_ip = posted_data['router_public_ip']
        con_request.router_public_port = posted_data['router_public_port']
        con_request.save()

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
            self.ad = get_object_or_404(AD, id=self.kwargs['pk'])
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


def download_approved_package(request, req_id):
    ad_request = get_object_or_404(ConnectionRequest, id=req_id)
    _check_user_permissions(request, ad_request.new_ad)
    if not ad_request.is_approved():
        raise PermissionDenied('Request is not approved')
    return _download_file_response(ad_request.package_path)


def approve_request(ad, ad_request):
    # Create the new AD
    new_id = AD.objects.latest('id').id + 1
    new_ad = AD.objects.create(id=new_id, isd=ad.isd,
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


@transaction.atomic
@require_POST
def request_action(request, req_id):
    """
    Approve or decline the sent connection request.
    """
    ad_request = get_object_or_404(ConnectionRequest, id=req_id)
    ad = ad_request.connect_to
    _check_user_permissions(request, ad)

    if '_approve_request' in request.POST:
        if not ad_request.is_approved():
            approve_request(ad, ad_request)
    elif '_decline_request' in request.POST:
        ad_request.status = 'DECLINED'
    else:
        return HttpResponseNotFound('Action not found')
    ad_request.save()
    return redirect(reverse('ad_connection_requests', args=[ad.id]))


@login_required
def list_sent_requests(request):
    """
    List requests, sent by the current user.
    """
    user = request.user
    sent_requests = user.connectionrequest_set.all()
    return render(request, 'ad_manager/sent_requests.html',
                  {'sent_requests': sent_requests})


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
    pov_ad = get_object_or_404(AD, id=pk)
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


def makeAS(request):
    url = 'http://localhost:8080/api/as/insert/%s/%s' % (login_key, login_secret)
    AS = {'isdas':"1-1", 'core':1}
    headers = {'content-type': 'application/json'}
    r = requests.post(url, json=AS, headers=headers)
    response = r.text
    return HttpResponse(response)


def upload_join_replies(args, core_isd_as):
    # Iterate through all the join requests you ('core_isd_as') received
    # and generate replies for each one of them
    replies = []
    isd_id, as_id = core_isd_as.split('-')
    ad = AD.objects.get(id=as_id, isd=isd_id)
    sig_priv_key = base64.b64decode(ad.sig_priv_key)

    for arg in args:
        sig_key = base64.b64decode(arg['sigkey'])
        enc_key = base64.b64decode(arg['enckey'])
        request_id = arg['id']
        isd_as = isd_id + '-' + str(request_id)
        certificate = Certificate.from_values(isd_as, sig_key, enc_key,
                                              core_isd_as, sig_priv_key, 0)
        reply = {
                    'request_id': request_id,
                    'certificate': str(certificate),
                    'trc': 'Fake TRC', #Your TRC file, that of the core AS
                    'trc_version': 0
                }
        replies.append(reply)

    # Upload these join replies to the SCION coord service
    url = urljoin(settings.SCION_COORD_BASE_URL,
                  settings.UPLOAD_JOIN_REPLIES_SVC)
    url += "/" + login_key + "/" + login_secret
    params = {
                'isdas': core_isd_as,
                'replies':replies
             }
    headers = {'content-type': 'application/json'}
    r = requests.post(url, json=params, headers=headers)

    if r.status_code != 200 :  # Debug
        print("Failed to upload join replies (Core ISD_AS: ", core_isd_as, ")")
    return HttpResponse(r.text)


@require_POST
def upload_conn_requests(request):
    return


def upload_conn_replies(args, isd_as):
    # Iterate through all the connection requests you received, and generate
    # replies for each one of them. For now, we neglect unauthenticated
    # requests and create new ER and send its IP/port details for authenticated
    # requests.
    # TODO(shyamjvs): Choose the ER's public IP/port from a table of available
    # IP/port pairs instead of randomly generating them.
    isd_id, as_id = isd_as.split('-')
    curr_as = get_object_or_404(AD, id=as_id)
    conn_replies = []

    for arg in args:
        cert_to_verify = Certificate.from_dict(json.loads(arg['certificate']))
        cert_chain = CertificateChain.from_values(cert_to_verify)
         # TODO(shyamjvs): Obtain trc and its version from AD model
        trc = 'Your trc'
        trc_version = 0

        if cert_chain.verify(cert_to_verify.subject, trc, trc_version):
            # Fetch the AS's current topology and add a new ER entry to it
            as_topo = curr_as.generate_topology_dict()

            elem_id = "er%ser%s" % (isd_as, arg['requester_isdas'])
            er_id = arg['id']
            er_local_addr = '127.0.0.' + str(random.randint(5, 250)) + '/29'
            er_local_port = random.randint(30050, 30100)
            er_public_addr = '127.0.0.' + str(random.randint(5, 250)) + '/31'
            er_public_port = SCION_ROUTER_PORT

            requester_isdas = arg['requester_isdas']
            requester_addr = arg['ip']
            requester_port = arg['port']

            link_type = ''
            if arg['linktype'] == 'CHILD':
                link_type = 'PARENT'
            elif arg['linktype'] == 'PARENT':
                link_type = 'CHILD'
            else:
                link_type = 'PEER'
            bandwidth = arg['bandwidth']
            mtu = arg['mtu']

            as_topo['EdgeRouters'][elem_id] = {
                'Addr': er_local_addr,
                'Port': er_local_port,
                'Interface': {
                    'IFID': er_id,
                    'Addr': er_public_addr,
                    'UdpPort': er_public_port,
                    'ISD_AS': requester_isdas,
                    'ToAddr': requester_addr,
                    'ToUdpPort': requester_port,
                    'LinkType': link_type,
                    'Bandwidth': bandwidth,
                    'MTU': mtu,
                }
            }

            # Write back the new AS topology to the database and to 'gen'
            os.makedirs(static_tmp_path, exist_ok=True)
            mask_dns = as_topo.pop('DNSServers')
            with open(yaml_topo_path, 'w') as file:
                yaml.dump(as_topo, file, default_flow_style=False)

            create_local_gen(isd_as, as_topo)
            as_topo['DNSServers'] = mask_dns
            generate_ansible_hostfile(topology_params, as_topo, isd_as)
            curr_as.fill_from_topology(as_topo, clear=True)

            # Create a connection reply for the requester
            conn_reply = {
                        'request_id': arg['id'],
                        'ip': er_public_addr,
                        'port': er_public_port,
                        'mtu': mtu,
                        'bandwidth': bandwidth,
                    }
        else:
            conn_reply = {
                        'request_id': arg['id'],
                        'ip': '',
                        'mtu': 0,
                        'port': 0,
                        'bandwidth': 0,
                    }
        conn_replies.append(reply)

    # Upload these connection replies to the SCION coord service
    url = urljoin(settings.SCION_COORD_BASE_URL,
                  settings.UPLOAD_CONN_REPLIES_SVC)
    url += "/" + login_key + "/" + login_secret
    params = {
                "isdas": isd_as,
                "certificate": curr_as.certificate,
                "replies": conn_replies,                
             }
    headers = {'content-type': 'application/json'}
    r = requests.post(url, json=params, headers=headers)

    if r.status_code != 200 :  # Debug
        print("Failed to upload conn replies (ISD_AS: ", isd_as, ")")
    return HttpResponse(r.text)


def poll_events(request):
    # Poll for any pending events for any AS under this instance of web scion.
    # If there indeed is a join/connection request directed towards an AS, then
    # forward the request to that AS asking it to upload back reply(ies).
    # TODO(shyamjvs): Run this function as a seperate thread from scion-web
    url = urljoin(settings.SCION_COORD_BASE_URL, settings.POLL_EVENTS_SVC)
    url += "/" + login_key + "/" + login_secret
    headers = {'content-type': 'application/json'}

    print("Poll running")
    while True:
        for ad in AD.objects.all():
            isd_as = str(ad.isd.id) + "-" + str(ad.id)
            print(type(isd_as), ":", isd_as)
            params = {
                        "isdas": isd_as,
                     }
            r = requests.post(url, json=params, headers=headers)

            print("status: ", r.status_code)
            if r.status_code != 200 :  # Debug
                print("Failed to poll for events (ISD_AS: ", isd_as, ")")

            req = json.loads(r.text)
            join_requests = req["join_requests"]
            conn_requests = req["conn_requests"]
            if join_requests:
                upload_join_replies(join_requests, isd_as)
            if conn_requests:
                upload_conn_replies(conn_requests, isd_as)
        sleep(settings.POLL_INTERVAL)
    print("Poll stopped")

def register_node(request):
    node_values = request.POST
    node_name = node_values['inputNodeName']
    last_seen = datetime.now()
    node_ip = node_values['inputNodeIP']
    node_isd = node_values['inputNodeISD']
    node_as = node_values['inputNodeAS']

    management_interface_ip = node_values['inputManagementInterfaceIP']

    result = run_rpc_command(node_ip, None, management_interface_ip, 'register',
                             node_isd, node_as)
    uuid = result['uuid']

    new_node, created = Node.objects. \
        get_or_create(uuid=uuid,
                      defaults={'name': node_name,
                                'last_seen': last_seen,
                                'IP': node_ip,
                                'ISD': node_isd,
                                'AS': node_as})
    if not created:
        new_node.last_seen = datetime.now
        new_node.save()

    current_page = request.META.get('HTTP_REFERER')
    return redirect(current_page)


def wrong_api_call(request):
    print('Wrong API call')
    return JsonResponse({'data': 'Failure'})


static_tmp_path = os.path.join(WEB_ROOT, 'ad_manager', 'static', 'tmp')
yaml_topo_path = os.path.join(static_tmp_path, 'topology.yml')


def st_int(s, default):
    s = s.strip()
    return int(s) if not s == '' else default


def name_entry_dict(name_list, address_list, port_list):
    ret_dict = {}
    for i in range(len(name_list)):
        ret_dict[name_list[i]] = {'Addr': address_list[i],
                                  'Port': st_int(port_list[i],
                                                 SCION_UDP_EH_DATA_PORT)}
    return ret_dict


def name_entry_dict_router(isd_as, tp):
    ret_dict = {}

    # Obtain the list of fields for the ER connections requested
    name_list = tp.getlist('inputEdgeRouterName')
    address_list = tp.getlist('inputEdgeRouterAddress')
    port_list = tp.getlist('inputEdgeRouterPort')
    interface_list = tp.getlist('inputInterfaceAddr')
    bandwidth_list = tp.getlist('inputInterfaceBandwidth')
    if_id_list = tp.getlist('inputInterfaceIFID')
    remote_name_list = tp.getlist('inputInterfaceRemoteName')
    interface_type_list = tp.getlist('inputInterfaceType')
    link_mtu_list = tp.getlist('inputLinkMTU')
    own_port_list = tp.getlist('inputInterfaceOwnPort')
    remote_address_list = {}  # To be obtained
    remote_port_list = {}     # To be obtained

    print("yo routers: ", len(name_list))
    print("edge router name: ", name_list[0])
    # Create a list of connection requests from the above fields for only those
    # in which all the required fields are non-empty.
    nonemptylist = []
    for i in range(len(name_list)):
        if "" not in [name_list[i], address_list[i],
                      interface_list[i], remote_name_list[i]]:
            nonemptylist.append(i)

    if not nonemptylist:
        return {}

    conn_requests = []
    for i in nonemptylist:
        port_list[i] = st_int(port_list[i], SCION_ROUTER_PORT)
        bandwidth_list[i] = st_int(bandwidth_list[i], DEFAULT_BANDWIDTH)
        if_id_list[i] = st_int(if_id_list[i], 1)
        link_mtu_list[i] = st_int(link_mtu_list[i], DEFAULT_MTU)
        own_port_list[i] = st_int(own_port_list[i], SCION_ROUTER_PORT)
        conn_request = {'isdas': remote_name_list[i],
                        'ip': interface_list[i],
                        'port': own_port_list[i],
                        'bandwidth': bandwidth_list[i],
                        'linktype': interface_type_list[i],
                        'mtu': link_mtu_list[i]
                        }
        conn_requests.append(conn_request)

    # Upload the connection requests to scion-coord and obtain ids for them
    isd_id, as_id = isd_as.split('-')
    curr_as = get_object_or_404(AD, id=as_id)

    url = urljoin(settings.SCION_COORD_BASE_URL,
                  settings.UPLOAD_CONN_REQUESTS_SVC)
    url += "/" + login_key + "/" + login_secret    
    params = {
                'isd_as': isd_as,
                'certificate': curr_as.certificate,
                'conn_requests': conn_requests,
            }
    headers = {'content-type': 'application/json'}

    r = requests.post(url, json=params, headers=headers)    
    request_ids = json.loads(r.text)['ids']
    request_id_to_idx = {}
    for i in range(len(nonemptylist)):
        request_id_to_idx[request_id[i]] = nonemptylist[i]
    print("yo mama")

    # Poll for replies to the connection requests from scion-coord. Fill the
    # remote address and port details for the connections from the replies
    url = urljoin(settings.SCION_COORD_BASE_URL,
                  settings.POLL_CONN_REQUESTS_SVC)
    url += "/" + login_key + "/" + login_secret
    params = {
        'isdas' : isd_as
    }

    while request_ids:
        r = requests.post(url, json=params, headers=headers) 
        response = r.text
        if response != '{}':
            conn_replies = json.loads(response)['conn_replies']
            if not conn_replies:
                continue
            for conn_reply in conn_replies:
                request_id = conn_reply['request_id']
                request_idx = request_id_to_idx[request_id]

                cert_to_verify = Certificate.from_dict(
                        json.loads(conn_reply['certificate']))
                cert_chain = CertificateChain.from_values(cert_to_verify)
                # TODO(shyamjvs): Obtain trc and its version from AD model
                trc = 'Your trc'
                trc_version = 0
                if cert_chain.verify(cert_to_verify.subject, trc, trc_version):
                    remote_address_list[request_idx] = conn_reply['ip']
                    remote_port_list[request_idx] = st_int(conn_reply['port'],
                                                           SCION_ROUTER_PORT)
                    link_mtu_list[request_idx] = min(
                        conn_reply['mtu'], link_mtu_list[request_idx])
                    bandwidth_list[request_idx] = min(
                        conn_reply['bandwidth'], bandwidth_list[request_idx])
                else:
                    remote_address_list[request_idx] = ''
                    remote_port_list[request_idx] = ''
                    print('Invalid Certificate for response to request_id: ',
                          request_id)
                request_ids.remove(request_id)
        sleep(2)

    # Now fill in all details for the ER connections since you now know remote
    # ERs' IPs and ports. Neglect a connection request if the remote IP/port
    # field received is empty.
    for j in range(len(nonemptylist)):
        i = nonemptylist[j]
        if remote_address_list[i] == '' or remote_port_list[i] == '':
            continue
        ret_dict[name_list[i]] = {'Addr': address_list[i],
                                  'Port': port_list[i],
                                  'Interface':
                                      {'Addr': interface_list[i],
                                       'Bandwidth': bandwidth_list[i],
                                       'IFID': if_id_list[i],
                                       'ISD_AS': remote_name_list[i],
                                       'LinkType': interface_type_list[i],
                                       'MTU': link_mtu_list[i],
                                       'ToAddr': remote_address_list[i],
                                       'ToUdpPort': remote_port_list[i],
                                       'UdpPort': own_port_list[i]
                                      }
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
                     'PathServer', 'SibraServer']  # 'DomainServer', tmp fix
    # until the discovery replaces it
    mockup_dicts['DNSServers'] = {'1': {'Addr': '127.0.0.1', 'Port': -1}}

    for s_type in service_types:
        section_name = s_type+'s' if s_type != 'DomainServer' else 'DNSServers'
        mockup_dicts[section_name] = \
            name_entry_dict(tp.getlist('input{}Name'.format(s_type)),
                            tp.getlist('input{}Address'.format(s_type)),
                            tp.getlist('input{}Port'.format(s_type))
                            )

    mockup_dicts['DnsDomain'] = tp['inputDnsDomain']
    mockup_dicts['EdgeRouters'] = name_entry_dict_router(isd_as, tp)
    mockup_dicts['ISD_AS'] = tp['inputISD_AS']
    mockup_dicts['MTU'] = st_int(tp['inputMTU'], DEFAULT_MTU)

    # Zookeeper special case
    s_type = 'ZookeeperServer'
    zk_dict = name_entry_dict(tp.getlist('input{}Name'.format(s_type)),
                              tp.getlist('input{}Address'.format(s_type)),
                              tp.getlist('input{}Port'.format(s_type))
                              )
    named_keys = list(zk_dict.keys())  # copy 'named' keys
    int_key = 1  # dict keys get replaced with numeric keys, 1 based
    for key in named_keys:
        zk_dict[int_key] = zk_dict.pop(key)
        int_key += 1

    mockup_dicts['Zookeepers'] = zk_dict

    # IP:port uniqueness in AS check
    all_ip_port_pairs = []
    for r in ['BeaconServers', 'CertificateServers',  # 'DNSServers', tmp fix
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
    # tmp fix DNSServer
    mask_dns = mockup_dicts.pop('DNSServers')
    with open(yaml_topo_path, 'w') as file:
        yaml.dump(mockup_dicts, file, default_flow_style=False)

    create_local_gen(isd_as, mockup_dicts)
    # tmp fix DNSServer
    mockup_dicts['DNSServers'] = mask_dns
    generate_ansible_hostfile(topology_params, mockup_dicts, isd_as)

    curr_as = get_object_or_404(AD, id=as_id)
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
    result = subprocess.check_call([scion_sh_path, 'topology', '-c', topo_path],
                                   cwd=PROJECT_ROOT)
    return result


def handle_uploaded_file(f):
    local_gen_path = os.path.join(WEB_ROOT, 'gen')
    os.makedirs(local_gen_path, exist_ok=True)  # create the folder if not there
    destination_file_path = os.path.join(local_gen_path, f.name)
    write_out_inmemory_uploaded(f, destination_file_path)

    create_global_gen(destination_file_path)  # to get the trc file


@require_POST
def upload_file(request):
    current_page = request.META.get('HTTP_REFERER')
    if request.method == 'GET':
        form = UploadFileForm()
        return render(request, 'isd_list.html', {'form': form})
    elif request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            handle_uploaded_file(request.FILES['file'])
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
            'domain_server': DNS_SERVICE,
            'sibra_server': SIBRA_SERVICE,
            'zookeeper_service': ZOOKEEPER_SERVICE}


def lookup_dict_executables():
    return {'router': ROUTER_EXECUTABLE,
            'beacon_server': BEACON_EXECUTABLE,
            'path_server': PATH_EXECUTABLE,
            'certificate_server': CERTIFICATE_EXECUTABLE,
            'domain_server': DNS_EXECUTABLE,
            'sibra_server': SIBRA_EXECUTABLE,
            'zookeeper_service': ZOOKEEPER_EXECUTABLE}


@require_POST
def deploy_config(request):
    """
    Finalize and deploy tar
    """
    tar_params = request.POST.copy()
    node_uuid = tar_params['nodeUUID']
    node = Node.objects.get(uuid=node_uuid)
    types = tar_params.getlist('type[]')
    management_interface_ip = tar_params['managementInterfaceIP']

    # looks up the name of the executable for the service,
    # certificate server -> 'cert_server', ...
    lkx = lookup_dict_executables()

    # looks up the prefix used for naming supervisor processes,
    # beacon server -> 'bs', ...
    lkp = lookup_dict_services_prefixes()

    tmp_folder_path = os.path.join(WEB_ROOT, 'ad_manager',
                                   'static', 'tmp')

    current_node_file = os.path.join(tmp_folder_path, node_uuid + '.tar')
    create_tar(current_node_file)

    for service_type in types:
        config = configparser.ConfigParser()
        prefix = lkp[service_type]
        executable_name = lkx[service_type]
        # Get digits only from ISD and AS names
        lkp['d'] = lambda x: ''.join(filter(str.isdigit(), x))
        serv_name = '{}{}-{}-1'.format(prefix, lkp['d'](node.ISD),
                                       lkp['d'](node.AS))
        config['program:' + serv_name] = \
            {'startsecs': '5',
             'command': '"bin/{0}" "{1}" "gen/{2}/{3}/{1}"'.format(
                 executable_name, serv_name, node.ISD, node.AS),
             'startretries': '0',
             'stdout_logfile': 'logs/' + serv_name + '.OUT',
             'redirect_stderr': 'true',
             'autorestart': 'false',
             'environment': 'PYTHONPATH =.',
             'autostart': 'false',
             'stdout_logfile_maxbytes': '0'}

        # replace command entry if zookeeper special case
        if service_type == 'zookeeper_service':
            config['program:' + serv_name]['command'] = \
                '"java" "-cp"' \
                ' "gen/{2}/{3}/{1}:' \
                '/usr/share/java/jline.jar:' \
                '/usr/share/java/log4j-1.2.jar:' \
                '/usr/share/java/xercesImpl.jar:' \
                '/usr/share/java/xmlParserAPIs.jar:' \
                '/usr/share/java/netty.jar:' \
                '/usr/share/java/slf4j-api.jar:' \
                '/usr/share/java/slf4j-log4j12.jar:' \
                '/usr/share/java/{0}" ' \
                '"-Dzookeeper.log.file=logs/{1}.log" ' \
                '"org.apache.zookeeper.server.quorum.QuorumPeerMain" ' \
                '"gen/{2}/{3}/{1}/zoo.cfg"'.format(executable_name,
                                                   serv_name,
                                                   node.ISD,
                                                   node.AS)

        conf_file_path = os.path.join(tmp_folder_path, 'supervisord.conf')
        with open(conf_file_path, 'w') as configfile:
            config.write(configfile)

        cert_path = os.path.join(tmp_folder_path, 'certs_only')
        add_file_to_tar(cert_path, serv_name, current_node_file)
        # add instead data and zoo.cfg for zookeeper config
        add_file_to_tar(yaml_topo_path,
                        os.path.join('/' + serv_name, 'topology.yml'),
                        current_node_file)
        add_file_to_tar(conf_file_path,
                        os.path.join('/' + serv_name, 'supervisord.conf'),
                        current_node_file)

    run_rpc_command(node.IP, node.uuid, management_interface_ip, 'retrieve_tar',
                    node.ISD, node.AS)
    current_page = request.META.get('HTTP_REFERER')
    return redirect(current_page)


def create_local_gen_without_topo(as_info, sig_priv_key, enc_priv_key):
    """
    creates the usual gen folder structure for an ISD/AS under web_scion/gen,
    but without the topology.yml file
    Args:
        isd_as: isd-as string
    """
    # Create a new directory for the AS in WEB_ROOT/... (overwrite if exists)
    isd_id, as_id = as_info['isdas'].split('-')
    as_path = os.path.join(WEB_ROOT, GEN_PATH,
                           'ISD{}/AS{}'.format(isd_id, as_id))
    rmtree(as_path, True)
    os.makedir(as_path)

    # Create keys and cert files inside the AS directory (in temporary dirs)
    # Note: These directories are moved into the node directories when topology
    # is generated for the AS.
    cert_file = get_cert_chain_file_path(as_path,
                                         [isd_id, as_id],
                                         as_info['cert_version'])
    trc_file = get_trc_file_path(as_path,
                                 isd_id,
                                 as_info['trc_version'])
    sig_key_file = get_sig_key_file_path(as_path)
    enc_key_file = get_enc_key_file_path(as_path)

    write_file(cert_file, as_info['certificate'])
    write_file(trc_file, as_info['trc'])
    write_file(sig_key_file, sig_priv_key)
    write_file(enc_key_file, enc_priv_key)

    #





def create_local_gen(isd_as, tp):
    """
    creates the usual gen folder structure for an ISD/AS under web_scion/gen,
    ready for Ansible deployment
    Args:
        isd_as: isd-as string
        tp: the topology file as a dict of dicts

    """
    # looks up the name of the executable for the service,
    # certificate server -> 'cert_server', ...
    lkx = lookup_dict_executables()

    isd_id, as_id = isd_as.split('-')

    local_gen_path = os.path.join(WEB_ROOT, 'gen')

    # Add the dispatcher folder in sub/web/gen/ if not already there
    dispatcher_folder_path = os.path.join(local_gen_path, 'dispatcher')
    if not os.path.exists(dispatcher_folder_path):
        copytree(os.path.join(PROJECT_ROOT, 'gen', 'dispatcher'),
                 dispatcher_folder_path)

    # TODO: Cert distribution needs integration with scion-coord,
    # using bruteforce copying over some gen certs and
    # matching keys to get Ansible testing
    # before integration with scion-coord
    shared_files_path = os.path.join(local_gen_path, 'shared_files')

    rmtree(os.path.join(shared_files_path), True)  # rm shared_files & content
    # populate the shared_files folder with the relevant files for this AS
    certgen_path = os.path.join(PROJECT_ROOT,
                                'gen/ISD{}/AS{}/endhost/'.format(isd_id, as_id))
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

    dict_keys = ['BeaconServers', 'CertificateServers', 'EdgeRouters',
                 'PathServers', 'SibraServers', 'Zookeepers']

    types_keys = zip(types, dict_keys)
    zk_name_counter = 1

    for service_type, type_key in types_keys:
        config = configparser.ConfigParser()
        executable_name = lkx[service_type]
        replicas = tp[type_key].keys()  # SECURITY WARNING:allows arbitrary path
        # the user can enter arbitrary paths for his output
        # might want to sanitize at least for '.', '\\' and variations
        for serv_name in replicas:
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
                config['program:' + serv_name]['command'] = \
                    '"java" "-cp"' \
                    ' "gen/{2}/{3}/{1}:' \
                    '/usr/share/java/jline.jar:' \
                    '/usr/share/java/log4j-1.2.jar:' \
                    '/usr/share/java/xercesImpl.jar:' \
                    '/usr/share/java/xmlParserAPIs.jar:' \
                    '/usr/share/java/netty.jar:' \
                    '/usr/share/java/slf4j-api.jar:' \
                    '/usr/share/java/slf4j-log4j12.jar:' \
                    '/usr/share/java/{0}" ' \
                    '"-Dzookeeper.log.file=logs/{1}.log" ' \
                    '"org.apache.zookeeper.server.quorum.QuorumPeerMain" ' \
                    '"gen/ISD{2}/AS{3}/{1}/zoo.cfg"'.format(executable_name,
                                                            serv_name,
                                                            isd_id,
                                                            as_id)

            node_path = 'ISD{}/AS{}/{}'.format(isd_id, as_id, serv_name)
            node_path = os.path.join(local_gen_path, node_path)
            # os.makedirs(node_path, exist_ok=True)
            if not os.path.exists(node_path):
                copytree(os.path.join(shared_files_path), node_path)
            conf_file_path = os.path.join(node_path, 'supervisord.conf')
            with open(conf_file_path, 'w') as configfile:
                config.write(configfile)

            # copy AS topology.yml file into node
            copy(yaml_topo_path, node_path)
            # Generating only the needed intermediate parts
            # not used as for now we generator.py all certs and keys resources
            # (minimaly required are only the certs and keys folders.
            # path_policy.yml can be copied over from PathPolicy.yml,
            # and as.yml is only a dict dump with a random master key)

            # tmp_cert_gen_path = os.path.join(PROJECT_ROOT, 'web_scion',
            # 'tmp_cert_gen')
            # os.makedirs(tmp_cert_gen_path, exist_ok=True)
            # copy(yaml_topo_path, tmp_cert_gen_path)
            #
            # topo_config = os.path.join(tmp_cert_gen_path, 'topology.yml')
            # path_policy = DEFAULT_PATH_POLICY_FILE
            # mininet = False
            # network = "127.0.0.0/8"
            # output_dir = tmp_cert_gen_path
            # zk_config = os.path.join(PROJECT_ROOT, 'topology/Zookeeper.yml')
            # confgen = ConfigGenerator(
            #     output_dir, topo_config, path_policy, zk_config,
            #     network, mininet)
            # confgen.generate_all()


def run_remote_command(ip, process_name, command):
    use_ansible = True

    if not use_ansible:
        server = xmlrpc.client.ServerProxy('http://{}:9011'.format(ip))
        wait_for_result = True
        succeeded = False
        if command == 'retrieve_tar':
            succeeded = server.supervisor.startProcess(process_name,
                                                       wait_for_result)

        if command == 'STOP':
            succeeded = server.supervisor.stopProcess(process_name,
                                                      wait_for_result)
        if command == 'START':
            succeeded = server.supervisor.startProcess(process_name,
                                                       wait_for_result)
        if command == 'STATUS':
            offset = 0
            length = 4000
            succeeded = server.supervisor.tailProcessStdoutLog(process_name,
                                                               offset, length)
        print('Remote operation {} completed: {}'.format(command, succeeded))
    else:
        # using the ansibleCLI instead of
        # duplicating code to use the PlaybookExecutor
        result = subprocess.check_call(['ansible-playbook',
                                        os.path.join(PROJECT_ROOT, 'ansible',
                                                     'deploy-ethz.yml'),
                                        '-f', '32'], cwd=PROJECT_ROOT)
        print(result)
    return 0


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
