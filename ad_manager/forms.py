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

# External packages
from django import forms

# SCION
from ad_manager.models import ConnectionRequest, AD, \
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

        ad = get_object_or_404(AD, id=current_as_id)
        remote_ip_choices = []

        if 'BorderRouters' in ad.original_topology.keys():
            for border_router in ad.original_topology['BorderRouters'].values():
                val = border_router['Interface']['ToAddr']
                remote_ip_choices.append((val, val))

        self.fields['router_public_ip'] = forms.ChoiceField(
            choices=remote_ip_choices
        )

    class Meta:
        model = ConnectionRequest
        fields = ('info', 'router_public_ip', 'router_public_port')
        # 'router_bound_ip','router_bound_port',
        labels = {'router_public_ip': 'Router external IP',
                  'router_public_port': 'Router external port'}
        # 'router_bound_ip': 'Router bound IP',


class NewLinkForm(forms.Form):
    link_types = ['PARENT', 'CHILD', 'PEER', 'ROUTING']

    end_point = forms.ModelChoiceField(
        queryset=AD.objects.none(),
        widget=forms.TextInput(attrs={'placeholder': 'AD id, for example, 20'})
    )
    link_type = forms.ChoiceField(choices=zip(link_types, link_types))

    def __init__(self, *args, **kwargs):
        self.from_ad = kwargs.pop('from_ad')
        assert isinstance(self.from_ad, AD)
        end_point_field = self.base_fields['end_point']
        end_point_field.queryset = AD.objects.exclude(id=self.from_ad.id)
        super().__init__(*args, **kwargs)
