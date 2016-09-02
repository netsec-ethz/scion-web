# Stdlib
import json
import tempfile
import os
import hashlib
from collections import deque
from shutil import rmtree

# External packages
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

import yaml
import tarfile
import configparser
import xmlrpc.client
import socket
from copy import deepcopy

# SCION
from guardian.shortcuts import assign_perm
from ad_manager.util.response_handling import (
    get_failure_errors,
    get_success_data,
    is_success,
)
from ad_manager.forms import (
    ConnectionRequestForm,
    NewLinkForm,
    UploadFileForm
)
from ad_manager.models import AD, ISD, ConnectionRequest
from ad_manager.util.ad_connect import (
    create_new_ad_files,
    find_last_router,
    # link_ads,
)
from ad_manager.util.errors import HttpResponseUnavailable
from lib.util import write_file
from topology.generator import ConfigGenerator  # , DEFAULT_PATH_POLICY_FILE,
# DEFAULT_ZK_CONFIG

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

DEFAULT_BANDWIDTH = 1000
SCION_SUGGESTED_PORT = 31000

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
    new_as_id = request.POST['inputASname']
    try:
        new_as_id = int(new_as_id)
    except ValueError:
        return JsonResponse({'data': 'Invalid AS id'})
    current_isd = request.POST['inputISDname']
    isd = get_object_or_404(ISD, id=int(current_isd))
    as_obj = AD.objects.create(id=new_as_id, isd=isd,
                               is_core_ad=0,
                               is_open=False)
    as_obj.save()
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
        context['sibra_servers'] = ad.sibraserverweb_set.all()

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
                         'sibra_servers']
        for list_name in lists_to_sort:
            context[list_name] = sorted(
                context[list_name],
                key=lambda el: el.name if el.name is not None else -1
            )

        # Connection requests tab
        context['received_requests'] = ad.received_requests.all()

        # Permissions
        context['user_has_perm'] = self.request.user.has_perm('change_ad', ad)
        return context


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

    response = run_remote_command(ad.md_host, proc_id, command,
                                  use_ansible=False)
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
                path = handle_uploaded_file(request.FILES['file'])
                reload_data_from_files([path])
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


def update_hash_var(isd_id, as_id, commit_hash):
    commit_hash = (commit_hash.split('|'))[0].strip()  # sanitize hash
    host_file_path = os.path.join(WEB_ROOT, 'gen',
                                  'ISD' + str(isd_id), 'AS' + str(as_id),
                                  'host.{}-{}'.format(isd_id, as_id))
    config = configparser.ConfigParser(allow_no_value=True, delimiters=' ',
                                       inline_comment_prefixes='#')
    try:
        config.read(host_file_path)
    except configparser.ParsingError:
        print('Tried to parse invalid host file at {}'.format(host_file_path))
        return

    for option in config['scion_nodes:vars']:  # remove obsolete entries
        if option.startswith('scion_version'):
            config.remove_option('scion_nodes:vars', option)
    config.set('scion_nodes:vars', 'scion_version={}'.format(commit_hash))

    with open(host_file_path, 'w') as configfile:
        config.write(configfile, space_around_delimiters=False)


@require_POST
def deploy(request, isd_id, as_id):
    # need to call Ansible for consistency check for isd_id, as_id on topo
    ansible_check = (lambda _isd_id, _as_id: True)  # mock
    commit_hash = request.POST['commitHash']
    # deploy with Ansible
    if ansible_check(isd_id, as_id):
        update_hash_var(isd_id, as_id, commit_hash)
        run_remote_command(None, None, None, use_ansible=True)
    current_page = request.META.get('HTTP_REFERER')
    return redirect(current_page)


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
