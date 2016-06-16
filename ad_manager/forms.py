# External packages
from django import forms
from django.forms import ModelChoiceField

# SCION
from ad_manager.models import PackageVersion, ConnectionRequest, AD

from django.shortcuts import get_object_or_404


class VersionChoiceField(ModelChoiceField):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.widget.attrs['style'] = 'height: 40px;'

    def label_from_instance(self, obj):
        assert isinstance(obj, PackageVersion)
        return "{} -- {}  ({:.2f} Mb)".format(obj.name, obj.date_created.date(),
                                              obj.size / 2 ** 20)


class PackageVersionSelectForm(forms.Form):
    selected_version = VersionChoiceField(
        empty_label=None,
        queryset=PackageVersion.objects.order_by('-date_created'),
    )


class ConnectionRequestForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        current_as_id = kwargs.pop('pk')
        super(ConnectionRequestForm, self).__init__(*args, **kwargs)

        ad = get_object_or_404(AD, id=current_as_id)
        remote_ip_choices = []

        if 'EdgeRouters' in ad.original_topology.keys():
            for edge_router in ad.original_topology['EdgeRouters'].values():
                val = edge_router['Interface']['ToAddr']
                remote_ip_choices.append((val, val))

        self.fields['router_public_ip'] = forms.ChoiceField(
            choices=remote_ip_choices
        )

    class Meta:
        model = ConnectionRequest
        fields = ('info', 'router_public_ip', 'router_public_port')
        # 'router_bound_ip','router_bound_port',
        labels = {'router_public_ip': 'Router external IP (leave blank if '
                                      'it is the same as the bound IP)',
                  'router_public_port': 'Router external port (leave blank if '
                                        'default or if not used)'}
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
