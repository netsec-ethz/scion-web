# External packages
from django import forms

# SCION
from ad_manager.models import ConnectionRequest, AD

from django.shortcuts import get_object_or_404


# never use for untrusted uploads
class UploadFileForm(forms.Form):
    file = forms.FileField()
    # filename = forms.CharField(max_length=25)  # additional field to rename f


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
