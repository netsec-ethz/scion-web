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
import hashlib
import json
import logging
import os
import posixpath
import socket
import subprocess
import tarfile
import time
import yaml
from collections import deque
from urllib.parse import urljoin

# External packages
from Crypto import Random
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
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

# SCION
from lib.crypto.asymcrypto import (
    generate_sign_keypair,
    generate_enc_keypair,
)
from lib.crypto.certificate import Certificate
from lib.crypto.certificate_chain import CertificateChain
from lib.crypto.trc import TRC
from lib.defines import (
    DEFAULT_MTU,
    PROJECT_ROOT,
)
from lib.packet.scion_addr import ISD_AS
from lib.types import LinkType
from lib.util import iso_timestamp
from topology.generator import INITIAL_CERT_VERSION

# SCION-WEB
from ad_manager.forms import (
    ConnectionRequestForm,
    CoordinationServiceSettingsForm,
    UploadFileForm,
)
from ad_manager.models import (
    AD,
    ConnectionRequest,
    ISD,
    JoinRequest,
    OrganisationAdmin,
    RouterWeb,
)
from ad_manager.util.hostfile_generator import generate_ansible_hostfile
from ad_manager.util.local_config_generator import (
    create_local_gen,
    WEB_ROOT,
)
from ad_manager.util.util import (
    from_b64,
    post_req_to_scion_coord,
    to_b64,
)
from ad_manager.util.defines import (
    COORD_SERVICE_URI,
    POLL_JOIN_REPLY_SVC,
    POLL_EVENTS_SVC,
    SCION_SUGGESTED_PORT,
    UPLOAD_CONN_REQUEST_SVC,
    UPLOAD_CONN_REPLY_SVC,
    UPLOAD_JOIN_REQUEST_SVC,
    UPLOAD_JOIN_REPLY_SVC,
)
from scripts.reload_data import reload_data_from_files


# Requests status
REQ_SENT = 'SENT'
REQ_APPROVED = 'APPROVED'
REQ_DECLINED = 'DECLINED'

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
def poll_join_reply(request):
    """
    Polls the join replies from SCION Coordination Service.
    :param HttpRequest request: Django Http Request passed on via the urls.py
    :returns: HTTP Response returned to the user.
    :rtype: HttpResponse
    """
    current_page = request.META.get('HTTP_REFERER')
    try:
        coord = OrganisationAdmin.objects.get(user_id=request.user.id)
    except OrganisationAdmin.DoesNotExist:
        logger.error("Retrieving account_id and secret failed.")
        return redirect(current_page)
    open_join_requests = JoinRequest.objects.filter(status=REQ_SENT)
    for req in open_join_requests:
        jr_id = req.id
        logger.info('Pending request = %s', jr_id)
        request_url = urljoin(COORD_SERVICE_URI, posixpath.join(
                              POLL_JOIN_REPLY_SVC, coord.account_id,
                              coord.secret))
        logger.info('url = %s' % request_url)
        r, error = post_req_to_scion_coord(request_url, {'request_id': jr_id},
                                           "poll join reply %s" % jr_id)
        if error is not None:
            return error
        handle_join_reply(request, r, jr_id)
    return redirect(current_page)


def handle_join_reply(request, reply, jr_id):
    """
    Handles the join reply coming through the SCION Coordination
    Service.
    :param HttpRequest request: Django Http Request passed on via the urls.py
    :param dict reply: Join Reply represented as dictionary.
    :param int jr_id: The ID of the join request.
    """
    join_reply = reply.json()
    if join_reply == {}:
        logger.info("Empty join reply for join request %s.", jr_id)
        return
    if join_reply['Status'] == REQ_APPROVED:
        # get the join request object which belong to this request
        # so that we can save the keys into the AS table.
        jr = JoinRequest.objects.get(id=jr_id)
        new_as = ISD_AS(join_reply['JoiningIA'])
        master_as_key = base64.b64encode(Random.new().read(16))
        isd, _ = ISD.objects.get_or_create(id=int(new_as[0]))
        AD.objects.update_or_create(
            as_id=new_as[1],
            isd=isd,
            is_core_ad=join_reply['IsCore'],
            is_open=False,
            certificate=join_reply['JoiningIACertificate'],
            trc=join_reply['TRC'],
            sig_pub_key=jr.sig_pub_key,
            sig_priv_key=jr.sig_priv_key,
            enc_pub_key=jr.enc_pub_key,
            enc_priv_key=jr.enc_priv_key,
            master_as_key=master_as_key.decode("utf-8")
        )
        messages.success(request, 'Created new AS: %s.' % new_as)
    else:
        messages.info(request, 'Your join request with ID %s is declined '
                               'by AS %s.' % (jr_id, join_reply['RespondIA']))
    # update join request's status based on the received join reply
    JoinRequest.objects.filter(id=jr_id).update(status=join_reply['Status'])


@require_POST
@login_required
def join_request_action(request, isd_as, request_id):
    """
    Approve or decline the join request.
    :param HttpRequest request: Django HTTP request passed on through urls.py
    :param str isd_as: ISD-AS who approves or declines the request
    :param str request_id: The ID of the Join Request in question.
    :returns: Django HTTP Response object.
    :rtype: HttpResponse.
    """
    if '_approve_request' in request.POST:
        return send_join_reply(request, REQ_APPROVED, isd_as, request_id)
    elif '_decline_request' in request.POST:
        return send_join_reply(request, REQ_DECLINED, isd_as, request_id)
    return HttpResponseNotFound('Invalid join request action')


@login_required
def send_join_reply(request, status, isd_as, request_id):
    """
    Accepts or declines the join request. In case of accept, it assigns a new
    AS ID to the requesting party and creates the certificate. This function
    is only executed by a core AS.
    """
    current_page = request.META.get('HTTP_REFERER')
    coord = get_object_or_404(OrganisationAdmin, user_id=request.user.id)
    own_isdas = ISD_AS(isd_as)
    own_as_obj = AD.objects.get(as_id=own_isdas[1], isd=own_isdas[0])
    if not own_as_obj.is_core_ad:
        logging.error("%s has to be a core AS to send join reply" % own_as_obj)
        return redirect(current_page)
    join_rep_dict = {
        'RequestId': int(request_id),
        'Status': status,
        'RespondIA': str(own_isdas),
        'RequesterId': request.POST['requester']
    }
    if status == REQ_APPROVED:
        prep_approved_join_reply(request, join_rep_dict, own_isdas, own_as_obj)
    else:
        logger.debug("Declining Join Request = %s", join_rep_dict)
    request_url = urljoin(COORD_SERVICE_URI, posixpath.join(
                          UPLOAD_JOIN_REPLY_SVC, coord.account_id,
                          coord.secret))
    _, error = post_req_to_scion_coord(request_url, join_rep_dict,
                                       "join reply %s" % request_id)
    if error is not None:
        return error
    return redirect(current_page)


def prep_approved_join_reply(request, join_rep_dict, own_isdas, own_as_obj):
    """
    Prepares the join reply for the APPROVED case.
    """
    logger.info("New AS ID = %s", request.POST['newASId'])
    joining_as = request.POST['newASId']
    is_core = request.POST['join_as_a_core']
    sig_pub_key = from_b64(request.POST['sig_pub_key'])
    enc_pub_key = from_b64(request.POST['enc_pub_key'])
    signing_as_sig_priv_key = from_b64(own_as_obj.sig_priv_key)
    joining_ia = ISD_AS.from_values(own_isdas[0], joining_as)
    cert = Certificate.from_values(
        str(joining_ia), str(own_isdas), INITIAL_CERT_VERSION, "", False,
        enc_pub_key, sig_pub_key, signing_as_sig_priv_key
    )
    respond_ia_chain = CertificateChain.from_raw(own_as_obj.certificate)
    request_ia_chain = CertificateChain([cert, respond_ia_chain.certs[0]])
    join_rep_dict['JoiningIA'] = str(joining_ia)
    join_rep_dict['IsCore'] = is_core.lower() == "true"
    join_rep_dict['RespondIA'] = str(own_isdas)
    join_rep_dict['JoiningIACertificate'] = request_ia_chain.to_json()
    join_rep_dict['RespondIACertificate'] = respond_ia_chain.to_json()
    join_rep_dict['TRC'] = TRC.from_raw(own_as_obj.trc).to_json()
    logger.debug("Accepting Join Request = %s", join_rep_dict)


@require_POST
@login_required
def request_join_isd(request):
    """
    Sends the join request to SCION Coordination Service.
    :param HttpRequest request: Django HTTP request passed on through urls.py.
    :returns: Django HTTP Response object.
    :rtype: HttpResponse.
    """
    current_page = request.META.get('HTTP_REFERER')
    # check the validity of parameters
    if not request.POST["inputISDToJoin"].isdigit():
        messages.error(request, 'ISD to join has to be a number!')
        return redirect(current_page)
    isd_to_join = int(request.POST["inputISDToJoin"])
    join_as_a_core = request.POST["inputJoinAsACore"]
    # get the account_id and secret necessary to query SCION-coord.
    coord = get_object_or_404(OrganisationAdmin, user_id=request.user.id)
    # generate the sign and encryption keys
    private_key_sign, public_key_sign = generate_sign_keypair()
    public_key_encr, private_key_encr = generate_enc_keypair()
    join_req = JoinRequest.objects.create(
        created_by=request.user,
        isd_to_join=isd_to_join,
        join_as_a_core=join_as_a_core.lower() == "true",
        sig_pub_key=to_b64(public_key_sign),
        sig_priv_key=to_b64(private_key_sign),
        enc_pub_key=to_b64(public_key_encr),
        enc_priv_key=to_b64(private_key_encr)
    )
    join_req_dict = {
        "RequestId": join_req.id,
        "IsdToJoin": isd_to_join,
        "JoinAsACoreAS": join_req.join_as_a_core,
        "SigPubKey": to_b64(public_key_sign),
        "EncPubKey": to_b64(public_key_encr)
    }
    request_url = urljoin(COORD_SERVICE_URI, posixpath.join(
                          UPLOAD_JOIN_REQUEST_SVC, coord.account_id,
                          coord.secret))
    _, error = post_req_to_scion_coord(request_url, join_req_dict,
                                       "join request %s" % join_req.id)
    if error is not None:
        return error
    logger.info("Request = %s, Join Request Dict = %s", request_url,
                join_req_dict)
    join_req.status = REQ_SENT
    join_req.save()
    messages.success(request, 'Join Request Submitted Successfully.'
                     ' Request ID = %s' % join_req.id)
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
        # get the account_id and secret necessary to query SCION-coord
        coord = get_object_or_404(OrganisationAdmin,
                                  user_id=self.request.user.id)
        # create connection_request db object
        con_req = self.create_req_obj(form)
        # prepare connection request dictionary to send
        con_req_dict = self.prepare_req_dict(con_req)
        logger.info("Sending Connection Request: %s", con_req_dict)
        # upload the req to scion-coord
        request_url = urljoin(COORD_SERVICE_URI, posixpath.join(
                              UPLOAD_CONN_REQUEST_SVC, coord.account_id,
                              coord.secret))
        _, error = post_req_to_scion_coord(
            request_url, con_req_dict, "connection request %s" % con_req.id)
        if error is not None:
            return error
        logging.info("Connection request %s successfully sent.",
                     con_req_dict['RequestId'])
        # set the status of the connection request to SENT
        con_req.status = REQ_SENT
        con_req.save()
        # update the success URL
        self.success_url = self._get_ad().get_absolute_url()
        return super().form_valid(form)

    def create_req_obj(self, form):
        """
        Creates the connection request object based on the form values and
        saves it into the database.
        :param ConnectionRequestForm form: The form containing the connection
        information
        :returns: Connection request object.
        :rtype: ConnectionRequest
        """
        data = self.request.POST
        con_req = form.instance
        con_req.connect_to = data['connect_to']
        connect_from = data['connect_from']
        con_req.connect_from = get_object_or_404(AD, as_id=connect_from)
        con_req.created_by = self.request.user
        con_req.router_info = data['router_info']
        con_req.overlay_type = data['overlay_type']
        con_req.router_public_ip = data['router_info'].split(':')[0]
        if "UDP" in con_req.overlay_type:
            con_req.router_public_port = data['router_info'].split(':')[1]
        else:
            con_req.router_public_port = None
        con_req.mtu = data['mtu']
        con_req.bandwidth = data['bandwidth']
        con_req.link_type = data['link_type']
        con_req.info = data['info']
        con_req.save()
        return con_req

    def prepare_req_dict(self, con_req):
        """
        Prepares the connection request as a dictionary to be sent to the SCION
        coordination service.
        :param ConnectionRequest con_req: Connection request object.
        :returns: Connection request as a dictionary.
        :rtype: dict
        """
        isd_as = ISD_AS.from_values(self._get_ad().isd.id,
                                    self._get_ad().as_id)
        cert_chain = CertificateChain.from_raw(self._get_ad().certificate)
        con_req_dict = {
            "RequestId": con_req.id,
            "Info": con_req.info,
            "RequestIA": str(isd_as),
            "RespondIA": con_req.connect_to,
            "IP": con_req.router_public_ip,
            "OverlayType": con_req.overlay_type,
            "MTU": int(con_req.mtu),
            "Bandwidth": int(con_req.bandwidth),
            "Timestamp": iso_timestamp(time.time()),
            "Signature": "",  # TODO(ercanucan): generate and set the signature
            "Certificate": cert_chain.to_json()
        }
        if con_req.router_public_port:
            con_req_dict["Port"] = int(con_req.router_public_port)
        # Adjust the link type for the receiving party (i.e if the requestIA
        # wants to have the respondIA as a PARENT, then the respondIA should
        # see it as a request to have a CHILD AS.
        if con_req.link_type == LinkType.PARENT:
            con_req_dict["LinkType"] = LinkType.CHILD
        elif con_req.link_type == LinkType.CHILD:
            con_req_dict["LinkType"] = LinkType.PARENT
        else:
            con_req_dict["LinkType"] = con_req.link_type
        return con_req_dict

    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        context_data['ad'] = self._get_ad()
        return context_data


@require_POST
def connection_request_action(request, con_req_id):
    """
    Responds to the received connection request with a connection reply.
    :param HttpRequest request: Django HTTP request.
    :param str con_req_id: The ID of the connection request
    :returns: HttpResponse depending on the outcome of sending the connection
    reply
    :rtype: HttpResponse
    """
    posted_data = request.POST
    respond_ia = ISD_AS(posted_data['RespondIA'])
    respond_as = get_object_or_404(AD, isd=respond_ia[0],
                                   as_id=respond_ia[1])
    _check_user_permissions(request, respond_as)
    if '_approve_request' in request.POST:
        send_connection_reply(request, con_req_id, REQ_APPROVED, respond_as,
                              posted_data)
        return redirect(reverse('ad_detail_topology_routers',
                                args=[respond_as.as_id]))
    elif '_decline_request' in request.POST:
        send_connection_reply(request, con_req_id, REQ_DECLINED, respond_as,
                              posted_data)
        return redirect(reverse('ad_connection_requests',
                                args=[respond_as.as_id]))
    return HttpResponseNotFound('Invalid connection request action')


@login_required
def send_connection_reply(request, con_req_id, status, respond_as, data):
    """
    Sends connection reply to SCION Coordination Service.
    :param HttpRequest request: Django HTTP Request.
    :param str con_req_id: The ID of the connection request to be replied to.
    :param str status: The status of the the request. (e.g APPROVED)
    :param str respond_as: The AS responding to the connection request.
    :param dict data: Dictionary object containing the reply parameters.
    """
    coord = get_object_or_404(OrganisationAdmin,
                              user_id=request.user.id)
    con_rep_dict = {
        "RequestId": int(con_req_id),
        "Status": status,
        "RequestIA": data['RequestIA'],
        "RespondIA": str(respond_as)
    }
    if status == REQ_APPROVED:
        router_info = data['router_info']
        overlay_type = data['accepted_overlay_type']
        con_rep_dict["IP"] = router_info.split(':')[0]
        if "UDP" in overlay_type:
            con_rep_dict["Port"] = int(router_info.split(':')[1])
        con_rep_dict["OverlayType"] = overlay_type
        con_rep_dict["MTU"] = int(data['accepted_mtu'])
        con_rep_dict["Bandwidth"] = int(data['accepted_bandwidth'])
        cert_chain = CertificateChain.from_raw(respond_as.certificate)
        con_rep_dict["Certificate"] = cert_chain.to_json()
    request_url = urljoin(COORD_SERVICE_URI, posixpath.join(
                          UPLOAD_CONN_REPLY_SVC, coord.account_id,
                          coord.secret))
    _, error = post_req_to_scion_coord(request_url, con_rep_dict,
                                       "connection reply %s" % con_req_id)
    if error is not None:
        return error
    logging.info("Connection reply %s successfully sent.",
                 con_rep_dict['RequestId'])


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
        context['received_conn_replies'] = {}
        try:
            coord = OrganisationAdmin.objects.get(user_id=self.request.user.id)
        except OrganisationAdmin.DoesNotExist:
            logger.error("Retrieving account_id and secret failed!!.")
            return context
        request_url = urljoin(COORD_SERVICE_URI, posixpath.join(
                              POLL_EVENTS_SVC, coord.account_id, coord.secret))
        logger.info("Polling Events for %s", context['isdas'])
        r, error = post_req_to_scion_coord(
            request_url, {'IsdAs': context['isdas']},
            "poll events for ISD-AS %s" % context['isdas'])
        if error is not None:
            messages.error(self.request, 'Could not poll events from SCION '
                           'Coordination Service!')
            return context
        resp = r.json()
        context['join_requests'] = resp['JoinRequests']
        context['received_requests'] = resp['ConnRequests']
        context['received_conn_replies'] = resp['ConnReplies']
        return context


@login_required
def add_to_topology(request):
    """
    Adds the router information which comes with a connection reply
    into the topology of the AS.
    :param HttpRequest request: Django HTTP request.
    """
    con_reply = json.loads(request.body.decode('utf-8'))
    # find the corresponding connection request from DB
    try:
        con_req = ConnectionRequest.objects.get(id=con_reply['RequestId'])
    except ConnectionRequest.DoesNotExist:
        logger.error("Connection request for reply with ID %s not found",
                     con_reply['RequestId'])
        return HttpResponseNotFound("Connection request for reply %s not found"
                                    % con_reply['RequestId'])
    # find the corresponding router
    ip = con_req.router_public_ip
    port = con_req.router_public_port
    try:
        router = RouterWeb.objects.get(addr=ip, interface_port=port)
    except RouterWeb.DoesNotExist:
        logger.error("Router for connection reply with ID %s not found.",
                     con_reply['RequestId'])
        return HttpResponseNotFound("Router for connection reply with ID %s "
                                    "not found." % con_reply['RequestId'])
    isd_id, as_id = ISD_AS(con_reply['RequestIA'])
    try:
        req_ia = AD.objects.get(isd_id=isd_id, as_id=as_id)
    except AD.DoesNotExist:
        logger.error("AS %s was not found." % con_reply['RequestIA'])
        return HttpResponseNotFound("AS %s was not found"
                                    % con_reply['RequestIA'])
    topo = req_ia.original_topology
    interface = topo['BorderRouters'][router.name]['Interface']
    interface['ToAddr'] = con_reply['IP']
    if "UDP" in con_reply['OverlayType']:
        interface['ToUdpPort'] = con_reply['Port']
    # TODO(ercanucan): verify the other parameters of the request as well?
    req_ia.save()
    # write the updated topology file
    create_local_gen(con_reply['RequestIA'], topo)
    # save the data into DB
    req_ia.fill_from_topology(topo, clear=True)
    return HttpResponse("Successfully added to topology of %s" % router.name)


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
        acc, created = OrganisationAdmin.objects.get_or_create(user_id=user.id)
        if created:
            acc.is_org_admin = True
        acc.account_id = form.cleaned_data['account_id']
        acc.secret = form.cleaned_data['secret']
        acc.save()
    return redirect(current_page)


def _get_partial_graph(pov_as, depth=1):
    partial_graph = {}
    bfs_queue = deque([[pov_as, depth]])
    while bfs_queue:
        next_as, as_depth = bfs_queue.popleft()
        if next_as in partial_graph:
            continue
        routers = next_as.routerweb_set.all()
        neighbors = []
        for router in routers:
            neighbor_as = _get_neighbor_as(router)
            if not neighbor_as:
                continue
            if as_depth > 0:
                bfs_queue.append([neighbor_as, as_depth - 1])
            neighbors.append(neighbor_as)
        partial_graph[next_as] = neighbors
    return partial_graph


def _get_neighbor_as(router):
    try:
        neighbor_as = AD.objects.get(isd_id=router.neighbor_isd_id,
                                     as_id=router.neighbor_as_id)
    except AD.DoesNotExist:
        # if the neighbor AS does not exist in the local DB, return None
        return None
    return neighbor_as


def _get_node_object(as_obj):
    node_object = {
        'name': 'AS %s-%s' % (as_obj.isd_id, as_obj.as_id),
        'group': as_obj.isd_id,
        'url': as_obj.get_absolute_url(),
        'networkUrl': reverse('network_view_as',
                              args=[as_obj.isd_id, as_obj.as_id]),
        'core': int(as_obj.is_core_ad),
    }
    return node_object


def network_view_neighbors(request, isd_id, as_id):
    pov_as = get_object_or_404(AD, isd_id=isd_id, as_id=as_id)
    depth = 2
    partial_graph = _get_partial_graph(pov_as, depth)
    as_with_neighbors = partial_graph.keys()
    # Build reverse index
    as_index_rev = {}
    for i, as_id in enumerate(as_with_neighbors):
        as_index_rev[as_id] = i
    graph = {'nodes': [], 'links': []}
    for as_obj in as_with_neighbors:
        index = as_index_rev[as_obj]
        neighbors = partial_graph[as_obj]
        node_object = _get_node_object(as_obj)
        if as_obj == pov_as:
            node_object['pov'] = 1
        graph['nodes'].append(node_object)
        for n in neighbors:
            if n not in as_index_rev:
                continue
            neighbor_id = as_index_rev[n]
            if index < neighbor_id:
                graph['links'].append({
                    'source': index,
                    'target': neighbor_id,
                    'value': 1,
                })
    return render(request, 'ad_manager/network_view.html',
                  {'data': graph,
                   'pov_as': pov_as})


def network_view(request):
    """
    Prepare network graph visualization.
    """
    all_ases = AD.objects.all()
    as_graph_tmp = []
    # Direct and reverse index <-> AS mappings
    as_index = {}
    as_index_rev = {}
    for i, as_obj in enumerate(all_ases):
        as_index[i] = as_obj
        as_index_rev[as_obj] = i
        routers = as_obj.routerweb_set.all()
        neighbors = []
        for router in routers:
            neighbor_as = _get_neighbor_as(router)
            if neighbor_as:
                neighbors.append(neighbor_as)
        as_graph_tmp.append(neighbors)
    # Build a list of [list of neighbors for every AS]
    as_graph = []
    for neighbors in as_graph_tmp:
        as_graph.append([as_index_rev[n] for n in neighbors])
    # Translate to D3.js format
    graph = {'nodes': [], 'links': []}
    for index, neighbors in enumerate(as_graph):
        as_obj = as_index[index]
        node_object = _get_node_object(as_obj)
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
        ret_dict[name_list[i]] = {
            'Addr': address_list[i],
            'Port': st_int(port_list[i], None),
            'Interface': {
                'Addr': interface_list[i],
                'Bandwidth': st_int(bandwidth_list[i], None),
                'IFID': st_int(if_id_list[i], None),
                'ISD_AS': remote_name_list[i],
                'LinkType': interface_type_list[i],
                'MTU': st_int(link_mtu_list[i], None),
                'ToAddr': remote_address_list[i],
                'ToUdpPort': st_int(remote_port_list[i], None),
                'UdpPort': st_int(own_port_list[i], None)
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
