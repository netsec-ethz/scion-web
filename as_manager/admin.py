# External packages
from django.conf import settings
from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth import get_permission_codename
from django.contrib.auth.models import User, Group
from django.core.urlresolvers import reverse
from guardian.admin import GuardedModelAdmin

# SCION
from two_factor.admin import AdminSiteOTPRequiredMixin
from two_factor.models import PhoneDevice
from as_manager.models import (
    OrganisationAdmin,
    AS,
    BeaconServerWeb,
    CertificateServerWeb,
    ConnectionRequest,
    ISD,
    PathServerWeb,
    RouterWeb,
    SibraServerWeb,
)


class MyAdminSite(AdminSite):
    def has_permission(self, request):
        """
        Every registered active user is allowed to view *at least* one page of
        the admin website.
        """
        return request.user.is_active


class MyAdminOTPSite(AdminSiteOTPRequiredMixin, MyAdminSite):
    pass


if settings.ENABLED_2FA:
    admin_site = MyAdminOTPSite(name='2fa_admin')
else:
    admin_site = MyAdminSite(name='basic_admin')
admin_site.register(User)
admin_site.register(Group)


class PrivilegedChangeAdmin(GuardedModelAdmin):
    list_select_related = True

    def has_change_permission(self, request, obj=None):
        opts = self.opts
        codename = get_permission_codename('change', opts)

        # If there is an 'ad' attribute then it's a foreign key, so extend
        # user permissions for this AS to the current object
        as_obj = getattr(obj, 'ad', None)
        if as_obj and isinstance(as_obj, AS):
            obj = as_obj
            codename = 'change_ad'
        return request.user.has_perm("%s.%s" % (opts.app_label, codename), obj)

    def get_readonly_fields(self, request, obj=None):
        """
        Make fields listed in 'privileged fields' read-only
        """
        fields = super().get_readonly_fields(request, obj)
        if not request.user.has_perm('change_ad'):
            fields += self.privileged_fields
        return fields

    def get_queryset(self, request):
        # Add ordering
        return super().get_queryset(request).order_by('id')


@admin.register(AS, ISD, OrganisationAdmin, site=admin_site)
class SortRelatedAdmin(PrivilegedChangeAdmin):
    privileged_fields = ('isd', 'is_core_as',)


@admin.register(BeaconServerWeb,
                CertificateServerWeb,
                PathServerWeb,
                SibraServerWeb,
                site=admin_site)
class ServerAdmin(PrivilegedChangeAdmin):
    fields = ('name', 'addr', ('as_obj', 'ad_link'),)
    privileged_fields = ('as_obj',)
    readonly_fields = ('as_link',)
    raw_id_fields = ('as_obj',)

    def as_link(self, obj):
        link = reverse('admin:{}_ad_change'.format(self.opts.app_label),
                       args=[obj.as_obj.id])
        return '<a href="{}">Edit AS</a>'.format(link)
    as_link.allow_tags = True
    # FIXME hack. How to remove this completely?
    as_link.short_description = ':'


@admin.register(RouterWeb, site=admin_site)
class RouterAdmin(ServerAdmin):
    list_display = ('as_obj', 'addr', 'neighbor_as', 'neighbor_type',
                    'interface_addr', 'interface_toaddr')

    def get_fields(self, request, obj=None):
        # FIXME is there a way to make it more explicit?
        self.raw_id_fields += ('neighbor_as',)
        fields = super().get_fields(request, obj)
        fields += ('interface_id',
                   ('interface_addr', 'interface_port'),
                   ('interface_toaddr', 'interface_toport'),
                   ('neighbor_as', 'neighbor_type'))
        return fields


# Misc admin models
admin_site.register(ConnectionRequest)
admin_site.register(PhoneDevice)
