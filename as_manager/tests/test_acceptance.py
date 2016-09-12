
# External packages
from django.conf import settings
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django_webtest import WebTest
from unittest.mock import patch

# SCION
from guardian.shortcuts import assign_perm
from as_manager.util.response_handling import response_success
from as_manager.models import ISD, AS, ConnectionRequest, OrganisationAdmin


class BasicWebTest(WebTest):

    fixtures = ['as_manager/tests/test_topology.json']

    def setUp(self):
        super().setUp()
        self.isds = {}
        for isd in ISD.objects.all():
            self.isds[isd.id] = isd

        self.ases = {}
        for as_obj in AS.objects.all():
            self.ases[as_obj.id] = as_obj

    def _get_as_detail(self, as_obj, *args, **kwargs):
        if isinstance(as_obj, AS):
            as_obj = as_obj.id
        assert isinstance(as_obj, int)
        return self.app.get(reverse('as_detail', args=[as_obj]), *args, **kwargs)

    def _find_form_by_action(self, response, view_name, *args, **kwargs):
        if args is None:
            args = []
        url = reverse(view_name, *args, **kwargs)
        all_forms = response.forms.values()
        form = next(filter(lambda f: f.action == url, all_forms))
        return form


class BasicWebTestUsers(BasicWebTest):

    def setUp(self):
        super().setUp()
        assert not settings.ENABLED_2FA
        self._create_users()

    def _create_users(self):
        self.admin_user = User.objects.create_superuser(username='admin',
                                                        password='admin',
                                                        email='')
        self.user = User.objects.create_user(username='user1',
                                             password='user1',
                                             email='')
        self.org_admin = OrganisationAdmin.objects.update_or_create(
            user=self.admin_user,
            is_org_admin=True,
            key="",
            secret=""
        )


class TestListIsds(BasicWebTest):

    def test_list_isds(self):
        isd_name = 'ISD 2'
        isd_list = self.app.get(reverse('list_isds'))
        self.assertContains(isd_list, isd_name)

        # Click on the isd link
        isd_detail = isd_list.click(isd_name)
        self.assertContains(isd_detail, isd_name)


class TestListAds(BasicWebTest):

    def test_list_ases(self):
        isd = self.isds[2]
        isd_name = 'ISD 2'
        as_list = self.app.get(reverse('isd_detail', args=[isd.id]))
        self.assertContains(as_list, isd_name)
        self.assertNotContains(as_list, str(self.ases[1]))

        for as_id in [3, 4, 5]:
            as_obj = self.ases[as_id]
            self.assertContains(as_list, str(as_obj))

    def test_list_core(self):
        isd = self.isds[2]
        as_obj = self.ases[3]
        as_obj.is_core_as = True
        as_obj.save()
        assert as_obj.isd == isd

        as_list = self.app.get(reverse('isd_detail', args=[isd.id]))
        self.assertContains(as_list, as_obj.id)
        li_tag = as_list.html.find('a', text='AS 2-3').parent
        self.assertIn('core', li_tag.text)


class TestAdDetail(BasicWebTest):

    def test_servers_page(self):
        as_obj = self.ases[1]
        as_detail = self._get_as_detail(as_obj)
        self.assertContains(as_detail, str(as_obj))
        html = as_detail.html
        beacon_servers = html.find(id="beacon-servers-table")
        certificate_servers = html.find(id="certificate-servers-table")
        path_servers = html.find(id="path-servers-table")
        routers = html.find(id="routers-table")

        # Test that tables are not empty
        tables = [beacon_servers, certificate_servers, path_servers, routers]
        for table in tables:
            assert table, 'No table found'
            self.assertFalse('No servers' in str(table), "Table is empty")

        # Test that all beacon servers are listed
        for bs in as_obj.beaconserverweb_set.all():
            assert bs.addr in beacon_servers.text

        # Test that routers are listed correctly
        router_rows = routers.find_all('tr')[1:]
        for r in as_obj.routerweb_set.all():
            row = next(filter(lambda x: r.addr in x.text, router_rows))
            assert str(r.neighbor_as) in row.text
            assert r.neighbor_type in row.text

        # Test that links to other ASes work
        as_2_detail = as_detail.click(str(self.ases[2]))
        self.assertEqual(as_2_detail.status_int, 200)
        self.assertContains(as_2_detail, str(self.ases[2]))

    def test_labels(self):
        as_obj = self.ases[1]
        value_map = {True: 'Yes', False: 'No'}

        # Test core label
        for is_core_value, page_value in value_map.items():
            as_obj.is_core_as = is_core_value
            as_obj.save()
            as_detail = self._get_as_detail(as_obj)
            core_container = as_detail.html.find(id='core-label')
            self.assertIn(page_value, core_container.text,
                          'Invalid label: core')


class TestUsersAndPermissions(BasicWebTestUsers):

    CONTROL_CLASS = 'process-control-form'

    def test_login_admin(self):
        as_detail = self._get_as_detail(self.ases[1])
        self.assertNotContains(as_detail, 'admin')
        login_page = as_detail.click('Login')
        login_form = login_page.form
        login_form['username'] = 'admin'
        login_form['password'] = 'admin'
        res = login_form.submit().follow()
        self.assertContains(res, 'AS 1')
        self.assertContains(res, 'Logged in as:')
        self.assertContains(res, 'admin')

    def test_admin_panel(self):
        admin_index = reverse('admin:index')
        # Anon user
        login_page = self.app.get(admin_index).follow()
        self.assertContains(login_page, 'Username:')

        # Non-admin user
        admin_page = self.app.get(admin_index, user=self.user)
        self.assertContains(admin_page, 'Site administration')
        self.assertContains(admin_page, "You don't have permission")

        # Admin user
        admin_page = self.app.get(admin_index, user=self.admin_user)
        self.assertContains(admin_page, 'Site administration')
        self.assertContains(admin_page, 'Authentication and Authorization')

    def test_login_logout(self):
        home = self.app.get('/', user=self.user).maybe_follow()
        res = home.click('logout').maybe_follow()
        self.assertContains(res, 'Login')

    def test_nonpriv_user_control(self):
        as_obj = self.ases[1]
        bs = as_obj.beaconserverweb_set.first()
        as_detail = self._get_as_detail(as_obj)

        # No control buttons
        self.assertFalse(as_detail.html.findAll('form', self.CONTROL_CLASS))

        # Action is forbidden
        control_url = reverse('control_process', args=[as_obj.id, bs.id_str()])
        res = self.app.post(control_url, expect_errors=True)
        self.assertEqual(res.status_code, 403)

    @patch("as_manager.views.run_remote_command")
    def test_priv_user_control(self, run_remote_command):
        as_obj = self.ases[1]
        bs = as_obj.beaconserverweb_set.first()
        as_detail = self._get_as_detail(as_obj, user=self.admin_user)

        self.assertTrue(as_detail.html.findAll('form', self.CONTROL_CLASS))

        # Find the bs control form
        bs_control_form = self._find_form_by_action(as_detail,
                                                    'control_process',
                                                    args=[as_obj.id, bs.id_str()])

        # Press the "start" button
        run_remote_command.return_value = response_success('ok')
        res = bs_control_form.submit('_start_process')
        self.assertTrue(res.json)


class TestConnectionRequests(BasicWebTestUsers):

    def _get_request_page(self, as_id):
        requests_page = reverse('as_connection_requests', args=[as_id])
        return requests_page

    def test_view_nopriv(self):
        as_obj = self.ases[2]
        requests_page = self._get_request_page(as_obj.id)

        # Anon user
        as_requests = self.app.get(requests_page)
        self.assertNotContains(as_requests, 'Received requests')
        self.assertNotContains(as_requests, 'Created by')

        # Non-priv user
        as_requests = self.app.get(requests_page, user=self.user)
        self.assertNotContains(as_requests, 'Received requests')
        self.assertNotContains(as_requests, 'Created by')

    def test_priv_user(self):
        as_obj = self.ases[2]
        requests_page = self._get_request_page(as_obj.id)

        # Admin user
        as_requests = self.app.get(requests_page, user=self.admin_user)
        self.assertContains(as_requests, 'Received requests')

        # User which has access to the AS
        assign_perm('change_ad', self.user, as_obj)
        as_requests = self.app.get(requests_page, user=self.user)
        self.assertContains(as_requests, 'Received requests')

    def test_send_request(self):
        as_obj = self.ases[2]
        as_obj.is_open = False
        as_obj.save()
        requests_page = self._get_request_page(as_obj.id)
        sent_requests_page = reverse('sent_requests')
        self.assertEqual(len(ConnectionRequest.objects.all()), 0)

        # Fill and submit the form
        as_requests = self.app.get(requests_page, user=self.admin_user)
        request_form = as_requests.click('New request').maybe_follow().form
        request_form['router_public_ip'] = '127.0.0.20'
        request_form['router_public_port'] = 12345
        request_form['info'] = 'test info'
        request_form.submit()
        self.assertEqual(len(ConnectionRequest.objects.all()), 1)
        request = ConnectionRequest.objects.first()
        self.assertEqual(request.created_by, self.admin_user)

        # Check that the sent request is listed at the 'sent requests' page
        sent_requests = self.app.get(sent_requests_page, user=self.admin_user)
        self.assertIn('submitted by admin', sent_requests.html.text)
        sent_table = sent_requests.html.find(id="sent-requests-tbl")
        for s in [as_obj, '127.0.0.20', 12345, 'test info', 'SENT']:
            self.assertIn(str(s), str(sent_table))

        # Check that the request is listed in the 'received' table
        # for admins and authorized users
        assign_perm('change_ad', self.user, as_obj)
        as_requests_admin = self.app.get(requests_page, user=self.admin_user)
        as_requests_user = self.app.get(requests_page, user=self.user)
        for response in [as_requests_admin, as_requests_user]:
            received_table = response.html.\
                find(id="received-connection-requests-tbl")
            for s in ['127.0.0.20', 'test info', 'SENT', 'admin']:
                self.assertIn(str(s), str(received_table))

    def test_decline_request(self):
        as_obj = self.ases[2]
        as_requests_page = self._get_request_page(as_obj.id)
        sent_requests_page = reverse('sent_requests')

        request = ConnectionRequest(created_by=self.user, connect_to=as_obj,
                                    info='test info', status='SENT',
                                    router_public_ip='123.123.123.123')
        request.save()

        as_requests = self.app.get(as_requests_page, user=self.admin_user)
        self.assertContains(as_requests, '123.123.123.123')
        sent_requests = self.app.get(sent_requests_page, user=self.user)
        self.assertContains(sent_requests, '123.123.123.123')

        control_form = self._find_form_by_action(as_requests,
                                                 'connection_request_action',
                                                 args=[request.id])
        as_requests = control_form.submit('_decline_request',
                                          user=self.admin_user).maybe_follow()
        self.assertContains(as_requests, 'DECLINED')
        sent_requests = self.app.get(sent_requests_page, user=self.user)
        self.assertContains(sent_requests, 'DECLINED')

        self.assertIsNone(request.package_path)


class TestNewLink(BasicWebTestUsers):

    def test_permissions(self):
        as_obj = self.ases[2]
        new_link_page = reverse('new_link', args=[as_obj.id])
        resp = self.app.get(new_link_page, user=self.admin_user)
        self.assertContains(resp, 'Link type')

        resp = self.app.get(new_link_page, user=self.user, expect_errors=True)
        self.assertEqual(resp.status_code, 403)
