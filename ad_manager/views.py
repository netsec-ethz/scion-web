# Stdlib
import copy
import json
import tempfile
import time
from collections import deque
from shutil import rmtree

# External packages
import dictdiffer
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

from datetime import datetime
import yaml
import tarfile
import configparser
import xmlrpc.client
import socket

# SCION
from guardian.shortcuts import assign_perm
from ad_management.common import PACKAGE_DIR_PATH
from ad_management.packaging import prepare_package
from ad_management.util import (
    get_failure_errors,
    get_success_data,
    is_success,
    response_failure,
)
from ad_manager.forms import (
    ConnectionRequestForm,
    NewLinkForm,
    PackageVersionSelectForm,
)
from ad_manager.models import AD, ISD, PackageVersion, ConnectionRequest, Node
from ad_manager.util import management_client
from ad_manager.util.ad_connect import (
    create_new_ad_files,
    find_last_router,
    link_ads,
)
from ad_manager.util.errors import HttpResponseUnavailable
from lib.util import write_file
from topology.generator import ConfigGenerator, DEFAULT_PATH_POLICY_FILE, DEFAULT_ZK_CONFIG

from scripts.reload_data import reload_data_from_files

from lib.defines import *
from lib.defines import GEN_PATH, PROJECT_ROOT

from ad_manager.util.hostfile_generator import generate_ansible_hostfile

import subprocess
from shutil import copy, copytree

GEN_PATH = os.path.join(PROJECT_ROOT, GEN_PATH)


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
        context = super().get_context_data(**kwargs)
        context['object'] = self.isd
        return context


@require_POST
def add_as(request):
    new_as_id = request.POST['inputASname']
    current_isd = request.POST['inputISDname']
    isd = get_object_or_404(ISD, id=int(current_isd))
    AS = AD.objects.create(id=new_as_id, isd=isd,
                           is_core_ad=0,
                           dns_domain='',
                           is_open=False)
    AS.save()
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

        context['nodes'] = Node.objects.all()
        context['management_interface_ip'] = get_own_local_ip()
        context['reloaded_topology'] = ad.original_topology
        context['as_id'] = ad.id
        context['isd_id'] = ad.isd_id

        # Sort by name numerically
        lists_to_sort = ['routers', 'path_servers',
                         'certificate_servers', 'beacon_servers',
                         'dns_servers']
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
    #form_class = ConnectionRequestForm
    template_name = 'ad_manager/new_connection_request.html'
    success_url = ''

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        current_as_id = kwargs['pk']

        form = ConnectionRequestForm(pk=current_as_id)
        context = self.get_context_data(form=form)
        return self.render_to_response(context)

    def _get_ad(self):
        return get_object_or_404(AD, id=self.kwargs['pk'])

    def form_valid(self, form):
        if not self.request.user.is_authenticated():
            return HttpResponseForbidden('Authentication required')

        connect_to = self._get_ad()
        form.instance.connect_to = connect_to
        form.instance.created_by = self.request.user
        form.save()

        con_request = form.instance
        con_request.status = 'SENT'

        if not con_request.router_public_ip:
            # Public = Bound
            con_request.router_public_ip = con_request.router_bound_ip
            con_request.router_public_port = con_request.router_bound_port
        con_request.save()

        self.success_url = reverse('sent_requests')
        if connect_to.is_open:
            # Create new AD
            approve_request(connect_to, con_request)

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
        from_ad = this_ad
        to_ad = form.cleaned_data['end_point']
        link_type = form.cleaned_data['link_type']

        if link_type == 'PARENT':
            from_ad, to_ad = to_ad, from_ad

        if link_type in ['CHILD', 'PARENT']:
            link_type = 'PARENT_CHILD'

        with transaction.atomic():
            link_ads(from_ad, to_ad, link_type)

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
        if ad_request.router_public_ip is None:
            ad_request.router_public_ip = ad_request.router_bound_ip

        if ad_request.router_public_port is None:
            ad_request.router_public_port = ad_request.router_bound_port

        _, new_topo_router = find_last_router(new_topo_dict)
        new_topo_router['Interface']['Addr'] = ad_request.router_bound_ip
        new_topo_router['Interface']['UdpPort'] = ad_request.router_bound_port

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
        package_dir = os.path.join(PACKAGE_DIR_PATH, 'AD' + str(new_ad))
        if os.path.exists(package_dir):
            rmtree(package_dir)
        os.makedirs(package_dir)

        # Prepare package
        package_name = 'scion_package_AD{}-{}'.format(new_ad.isd, new_ad.id)
        config_dirs = [os.path.join(temp_dir, x) for x in os.listdir(temp_dir)]
        ad_request.package_path = prepare_package(out_dir=package_dir,
                                                  config_paths=config_dirs,
                                                  package_name=package_name)
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


def register_node(request):
    node_values = request.POST
    node_name = node_values['inputNodeName']
    last_seen = datetime.now()
    node_ip = node_values['inputNodeIP']
    node_isd = node_values['inputNodeISD']
    node_as = node_values['inputNodeAS']

    management_interface_ip = node_values['inputManagementInterfaceIP']

    result = run_rpc_command(node_ip, None, management_interface_ip, 'register', node_isd, node_as)
    uuid = result['uuid']

    new_node, created = Node.objects.get_or_create(uuid=uuid, defaults={'name': node_name,
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


yaml_topo_path = os.path.join(PROJECT_ROOT, 'web_scion', 'ad_manager', 'static', 'tmp', 'topology.yml')


def st_int(s):
    s = s.strip()
    return int(s) if not s == '' else -1


@require_POST
def generate_topology(request):
    topology_params = request.POST.copy()
    topology_params.pop('csrfmiddlewaretoken', None)  # remove csrf entry, as we don't need it

    mockup_dicts = {}
    tp = topology_params
    isd_as = tp['inputISD_AS']
    isd_id, as_id = isd_as.split('-')
    mockup_dicts['BeaconServers'] = {tp['inputBeaconServerName']: {'Addr': tp['inputBeaconServerAddress'],
                                                                   'Port': st_int(tp['inputBeaconServerPort'])}}
    mockup_dicts['CertificateServers'] = {
        tp['inputCertificateServerName']: {'Addr': tp['inputCertificateServerAddress'],
                                           'Port': st_int(tp['inputBeaconServerPort'])}}
    mockup_dicts['Core'] = True if (tp['inputIsCore'] == 'on') else False
    mockup_dicts['DNSServers'] = {tp['inputDomainServerName']: {'Addr': tp['inputDomainServerAddress'],
                                                                'Port': st_int(tp['inputDomainServerPort'])}}
    mockup_dicts['DnsDomain'] = tp['inputDnsDomain']
    mockup_dicts['EdgeRouters'] = {tp['inputEdgeRouterName']: {'Addr': tp['inputEdgeRouterAddress'], 'Interface':
        {'Addr': tp['inputInterfaceAddr'],
         'Bandwidth': st_int(tp['inputInterfaceBandwidth']),
         'IFID': st_int(tp['inputInterfaceIFID']),
         'ISD_AS': tp['inputInterfaceRemoteName'], 'LinkType': tp['inputInterfaceType'],
         'ToAddr': tp['inputInterfaceRemoteAddress'],
         'ToUdpPort': st_int(tp['inputInterfaceRemotePort']),
         'UdpPort': st_int(tp['inputInterfaceOwnPort'])}}}
    mockup_dicts['ISD_AS'] = tp['inputISD_AS']
    mockup_dicts['MTU'] = st_int(tp['inputMTU'])
    mockup_dicts['PathServers'] = {
        tp['inputPathServerName']: {'Addr': tp['inputPathServerAddress'], 'Port': st_int(tp['inputPathServerPort'])}}
    mockup_dicts['SibraServers'] = {
        tp['inputSibraServerName']: {'Addr': tp['inputSibraServerAddress'], 'Port': st_int(tp['inputSibraServerPort'])}}
    mockup_dicts['Zookeepers'] = {
        1: {'Addr': tp['inputZookeeperServerAddress'], 'Port': st_int(tp['inputZookeeperServerPort'])}}

    all_IP_port_pairs = []
    for r in ['BeaconServers', 'CertificateServers', 'DNSServers', 'PathServers', 'SibraServers', 'Zookeepers']:
        servers_of_type_r = mockup_dicts[r]
        for server in servers_of_type_r:
            curr_pair = servers_of_type_r[server]['Addr'] + ':' + str(servers_of_type_r[server]['Port'])
            all_IP_port_pairs.append(curr_pair)
    if len(all_IP_port_pairs) != len(set(all_IP_port_pairs)):
        return JsonResponse({'data': 'IP:port combinations not unique within AS'})

    with open(yaml_topo_path, 'w') as file:
        yaml.dump(mockup_dicts, file, default_flow_style=False)

    create_local_gen(isd_as)
    generate_ansible_hostfile(topology_params, isd_as)

    curr_as = get_object_or_404(AD, id=as_id)
    curr_as.fill_from_topology(mockup_dicts)  # load as usual model (for display in overview)

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


def lookup_dict_services_prefixes():
    # looks up the prefix used for naming supervisor processes, beacon server -> 'bs', ... TODO: move to util
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

    # looks up the name of the executable for the service, certificate server -> 'cert_server', ...
    lkx = lookup_dict_executables()

    # looks up the prefix used for naming supervisor processes, beacon server -> 'bs', ...
    lkp = lookup_dict_services_prefixes()

    tmp_folder_path = os.path.join(PROJECT_ROOT, 'web_scion', 'ad_manager', 'static', 'tmp')

    current_node_file = os.path.join(tmp_folder_path, node_uuid + '.tar')
    create_tar(current_node_file)

    for service_type in types:
        config = configparser.ConfigParser()
        prefix = lkp[service_type]
        executable_name = lkx[service_type]
        # Get digits only from ISD and AS names
        lkp['d'] = lambda x: ''.join(filter(str.isdigit(), x))
        serv_name = '{}{}-{}-1'.format(prefix, lkp['d'](node.ISD), lkp['d'](node.AS))
        config['program:' + serv_name] = \
            {'startsecs': '5',
             'command': '"bin/{0}" "{1}" "gen/{2}/{3}/{1}"'.format(executable_name, serv_name, node.ISD, node.AS),
             'startretries': '0',
             'stdout_logfile': 'logs/' + serv_name + '.OUT',
             'redirect_stderr': 'true',
             'autorestart': 'false',
             'environment': 'PYTHONPATH =.',
             'autostart': 'false',
             'stdout_logfile_maxbytes': '0'}

        # replace command entry if zookeeper special case
        if service_type == 'zookeeper_service':
            config['program:' + serv_name]['command'] = '"java" "-cp"' \
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
        add_file_to_tar(yaml_topo_path, os.path.join('/' + serv_name, 'topology.yml'), current_node_file)
        add_file_to_tar(conf_file_path, os.path.join('/' + serv_name, 'supervisord.conf'), current_node_file)

    run_rpc_command(node.IP, node.uuid, management_interface_ip, 'retrieve_tar', node.ISD, node.AS)
    current_page = request.META.get('HTTP_REFERER')
    return redirect(current_page)


def create_local_gen(isd_as):
    """
    creates the usual gen folder structure for an ISD/AS under web_scion/gen, ready for Ansible deployment
    Args:
        isd_as: isd-as string

    """
    # looks up the name of the executable for the service, certificate server -> 'cert_server', ...
    lkx = lookup_dict_executables()

    # looks up the prefix used for naming supervisor processes, beacon server -> 'bs', ...
    lkp = lookup_dict_services_prefixes()

    isd_id, as_id = isd_as.split('-')

    local_gen_path = os.path.join(PROJECT_ROOT, 'web_scion', 'gen')

    dispatcher_folder_path = os.path.join(local_gen_path, 'dispatcher')
    if not os.path.exists(dispatcher_folder_path):
        copytree(os.path.join(PROJECT_ROOT, 'gen', 'dispatcher'), dispatcher_folder_path)

    # TODO: Cert distribution needs integration with scion-coord,
    # using bruteforce copying over some gen certs and matching keys to get Ansible testing
    # before integration with scion-coord
    shared_files_path = os.path.join(local_gen_path, 'shared_files')
    if not os.path.exists(shared_files_path):
        copytree(os.path.join(PROJECT_ROOT, 'gen/ISD1/AS10/bs1-10-1/'), shared_files_path)
        # remove files that are not shared
        os.remove(os.path.join(shared_files_path, 'supervisord.conf'))
        os.remove(os.path.join(shared_files_path, 'topology.yml'))


    types = ['router', 'beacon_server', 'path_server', 'certificate_server',
             'domain_server', 'sibra_server', 'zookeeper_service']

    for service_type in types:
        config = configparser.ConfigParser()
        prefix = lkp[service_type]
        executable_name = lkx[service_type]
        # Get digits only from ISD and AS names
        serv_name = '{}{}-{}-1'.format(prefix, isd_id, as_id)
        config['program:' + serv_name] = \
            {'startsecs': '5',
             'command': '"bin/{0}" "{1}" "gen/ISD{2}/AS{3}/{1}"'.format(executable_name, serv_name, isd_id, as_id),
             'startretries': '0',
             'stdout_logfile': 'logs/' + serv_name + '.OUT',
             'redirect_stderr': 'true',
             'autorestart': 'false',
             'environment': 'PYTHONPATH =.',
             'autostart': 'false',
             'stdout_logfile_maxbytes': '0'}

        # replace command entry if zookeeper special case
        if service_type == 'zookeeper_service':
            config['program:' + serv_name]['command'] = '"java" "-cp"' \
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
        #os.makedirs(node_path, exist_ok=True)
        if not os.path.exists(node_path):
            copytree(os.path.join(shared_files_path), node_path)
        conf_file_path = os.path.join(node_path, 'supervisord.conf')
        with open(conf_file_path, 'w') as configfile:
            config.write(configfile)

        # copy AS topology.yml file into node
        copy(yaml_topo_path, node_path)



    # Generating only the needed intermediate parts
    # not used as for now we generator.py all certs and keys resources
    # (minimaly required are only the certs and keys folders. path_policy.yml can be copied over from PathPolicy.yml,
    # and as.yml is only a dict dump with a random master key)

    # tmp_cert_gen_path = os.path.join(PROJECT_ROOT, 'web_scion', 'tmp_cert_gen')
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

    if (not use_ansible):
        server = xmlrpc.client.ServerProxy('http://{}:9011'.format(ip))
        wait_for_result = True
        succeeded = False
        if command == 'retrieve_tar':
            succeeded = server.supervisor.startProcess(process_name, wait_for_result)

        if command == 'STOP':
            succeeded = server.supervisor.stopProcess(process_name, wait_for_result)
        if command == 'START':
            succeeded = server.supervisor.startProcess(process_name, wait_for_result)
        if command == 'STATUS':
            offset = 0
            length = 4000
            succeeded = server.supervisor.tailProcessStdoutLog(process_name, offset, length)
        print('Remote operation {} completed: {}'.format(command, succeeded))
    else:
        # using the ansibleCLI instead of duplicating code to use the PlaybookExecutor
        result = subprocess.check_call(['ansible-playbook', os.path.join(PROJECT_ROOT, 'ansible', 'deploy-ethz.yml'),
                                        '-f', '32'], cwd=PROJECT_ROOT)
    return 0


def run_rpc_command(ip, uuid, management_interface_ip, command, ISD, AS):
    server = xmlrpc.client.ServerProxy('http://{}:9012'.format(ip))
    result = None
    if command == 'register':
        result = server.register(management_interface_ip, ISD, AS)
    elif command == 'retrieve_tar':
        result = server.retrieve_configuration(uuid, management_interface_ip, ISD, AS)
    else:
        print('Wrong command')
    print('Remote operation {} completed: {}'.format(command, 'True'))
    return result
