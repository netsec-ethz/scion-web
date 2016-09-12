# External packages
from django import forms

# SCION
from as_manager.models import ConnectionRequest, AS, \
    OrganisationAdmin

from django.shortcuts import get_object_or_404


# never use for untrusted uploads
class UploadFileForm(forms.Form):
    file = forms.FileField()
    # filename = forms.CharField(max_length=25)  # additional field to rename f


class CoordinationServiceSettingsForm(forms.Form):
    def __init__(self, *args, **kwargs):
        user_id = kwargs.pop('user_id')
        super().__init__(*args, **kwargs)

        try:
            coord_settings = OrganisationAdmin.objects.get(user_id=user_id)
        except OrganisationAdmin.DoesNotExist:
            coord_settings = OrganisationAdmin()
            coord_settings.key = 'Not set'
            coord_settings.secret = 'Not set'

        self.fields['key'] = forms.CharField(widget=forms.TextInput(
            attrs={'class': 'input-field-coord-key',
                   'value': coord_settings.key})
        )
        self.fields['secret'] = forms.CharField(widget=forms.TextInput(
            attrs={'class': 'input-field-coord-secret',
                   'value': coord_settings.secret})
        )

    class Meta:
        model = OrganisationAdmin
        fields = ('key', 'secret')
        labels = {'Key': 'Secret'}


class ConnectionRequestForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        current_as_id = kwargs.pop('pk')
        super(ConnectionRequestForm, self).__init__(*args, **kwargs)

        as_obj = get_object_or_404(AS, id=current_as_id)  # TD: request by as_id
        remote_ip_choices = []

        self.fields['connect_from'] = forms.CharField(
            widget=forms.HiddenInput(attrs={'value': current_as_id})
        )
        self.fields['connect_to'] = forms.CharField(
            widget=forms.TextInput(attrs={'placeholder':
                                          'ISD-AS of the AS to connect to'})
        )

        if 'BorderRouters' in as_obj.original_topology.keys():
            for border_router in as_obj.original_topology['BorderRouters'].\
                    values():
                val = border_router['Interface']['ToAddr']
                remote_ip_choices.append((val, val))

        self.fields['router_public_ip'] = forms.ChoiceField(
            choices=remote_ip_choices
        )

    class Meta:
        model = ConnectionRequest
        fields = ('connect_to', 'info', 'router_public_ip', 'router_public_port', 'mtu',
                  'bandwidth', 'link_type')
        # 'router_bound_ip','router_bound_port',
        labels = {'connect_to': 'Connect to',
                  'router_public_ip': 'Router external IP',
                  'router_public_port': 'Router external port',
                  'mtu': 'MTU',
                  'link_type': 'link type'}
        # 'router_bound_ip': 'Router bound IP',


class NewLinkForm(forms.Form):
    link_types = ['PARENT', 'CHILD', 'PEER', 'ROUTING']

    end_point = forms.ModelChoiceField(
        queryset=AS.objects.none(),
        widget=forms.TextInput(attrs={'placeholder': 'AS id, for example, 20'})
    )
    link_type = forms.ChoiceField(choices=zip(link_types, link_types))

    def __init__(self, *args, **kwargs):
        self.from_as = kwargs.pop('from_as')
        assert isinstance(self.from_as, AS)
        end_point_field = self.base_fields['end_point']
        end_point_field.queryset = AS.objects.exclude(as_id=self.from_as.as_id,
                                                      isd=self.from_as.isd)
        super().__init__(*args, **kwargs)
