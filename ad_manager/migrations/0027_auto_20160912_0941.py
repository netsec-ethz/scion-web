# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0026_auto_20160823_1558'),
    ]

    operations = [
        migrations.AddField(
            model_name='beaconserverweb',
            name='addr_internal',
            field=models.GenericIPAddressField(null=True, default=None),
        ),
        migrations.AddField(
            model_name='beaconserverweb',
            name='port_internal',
            field=models.IntegerField(null=True, default=None),
        ),
        migrations.AddField(
            model_name='certificateserverweb',
            name='addr_internal',
            field=models.GenericIPAddressField(null=True, default=None),
        ),
        migrations.AddField(
            model_name='certificateserverweb',
            name='port_internal',
            field=models.IntegerField(null=True, default=None),
        ),
        migrations.AddField(
            model_name='pathserverweb',
            name='addr_internal',
            field=models.GenericIPAddressField(null=True, default=None),
        ),
        migrations.AddField(
            model_name='pathserverweb',
            name='port_internal',
            field=models.IntegerField(null=True, default=None),
        ),
        migrations.AddField(
            model_name='routerweb',
            name='addr_internal',
            field=models.GenericIPAddressField(null=True, default=None),
        ),
        migrations.AddField(
            model_name='routerweb',
            name='port_internal',
            field=models.IntegerField(null=True, default=None),
        ),
        migrations.AddField(
            model_name='sibraserverweb',
            name='addr_internal',
            field=models.GenericIPAddressField(null=True, default=None),
        ),
        migrations.AddField(
            model_name='sibraserverweb',
            name='port_internal',
            field=models.IntegerField(null=True, default=None),
        ),
    ]
