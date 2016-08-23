# External packages
from django.conf.urls import patterns, url

# SCION
from ad_manager import views

api_patterns_internal = patterns(
    '',
    url(r'^api/v1/internal/isd/(?P<isd_id>\d+)/as/(?P<as_id>\d+)/topo_hash$',
        views.as_topo_hash, name='topo_hash'),
    url(r'^api/v1/internal/isd/(?P<isd_id>\d+)/as/(?P<as_id>\d+)/deploy$',
        views.deploy, name='deploy'),
    url(r'^api/v1/internal/.*$',
        views.wrong_api_call, name='wrong_api_call'),
)

api_patterns_external = patterns(
    # unimplemented API calls get treated as wrong API calls
    '',
    url(r'^api/v1/services_status$',
        views.wrong_api_call, name='services_status'),
    url(r'^api/v1/open_policy$',
        views.wrong_api_call, name='open_policy'),
    url(r'^api/v1/receive_notification$',
        views.wrong_api_call, name='receive_notification'),
    url(r'^api/v1/peering_request$',
        views.wrong_api_call, name='peering_request'),
    url(r'^api/v1/.*$',
        views.wrong_api_call, name='wrong_api_call'),  # Default route
)

isd_patterns = patterns(
    '',
    url(r'^isds/$',
        views.ISDListView.as_view(), name='list_isds'),
    url(r'^isds/upload_file$',
        views.upload_file, name='upload_file_ref'),
    url(r'^isds/add_isd$',
        views.add_isd, name='add_isd'),
    url(r'^isds/(?P<pk>\d+)/$',
        views.ISDDetailView.as_view(), name='isd_detail'),
)

ad_patterns = patterns(
    '',
    url(r'^ads/add_as$',
        views.add_as, name='add_as'),
    url(r'^ads/(?P<pk>\d+)/$',
        views.ADDetailView.as_view(), name='ad_detail'),
    url(r'^ads/(?P<pk>\d+)/#!topology$',
        views.ADDetailView.as_view(), name='ad_detail_topology'),
    url(r'^ads/(?P<pk>\d+)/#!updates$',
        views.ADDetailView.as_view(), name='ad_detail_updates'),
    url(r'^ads/(?P<pk>\d+)/#!requests$',
        views.ADDetailView.as_view(), name='ad_connection_requests'),
    url(r'^ads/(?P<pk>\d+)/control/(?P<proc_id>[\w-]+)/$',
        views.control_process, name='control_process'),
    url(r'^ads/(?P<pk>\d+)/log/(?P<proc_id>[\w-]+)/$',
        views.read_log, name='read_log'),
    url(r'^ads/(?P<pk>\d+)/new_link/$',
        views.NewLinkView.as_view(), name='new_link'),
    url(r'^ads/generate_topology$',
        views.generate_topology, name='generate_topology'),
)

connection_request_patterns = patterns(
    '',
    url(r'^connection_requests/new/(?P<pk>\d+)/$',
        views.ConnectionRequestView.as_view(), name='new_connection_request'),
    url(r'^connection_requests/sent$',
        views.list_sent_requests, name='sent_requests'),
    url(r'^connection_requests/(?P<req_id>\d+)/action/$',
        views.request_action, name='connection_request_action'),
)

misc = patterns(
    '',
    url(r'^network/$',
        views.network_view, name='network_view'),
    url(r'^network/(?P<pk>\d+)/$',
        views.network_view_neighbors, name='network_view_ad'),
)

urlpatterns = api_patterns_internal + isd_patterns + ad_patterns + \
              connection_request_patterns + misc
