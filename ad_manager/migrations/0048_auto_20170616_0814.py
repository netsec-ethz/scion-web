# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0047_borderrouter_borderrouteraddress_borderrouterinterface_service_serviceaddress'),
    ]

    operations = [
        migrations.RenameField(
            model_name='borderrouterinterface',
            old_name='bind_port',
            new_name='bind_l4port',
        ),
        migrations.RenameField(
            model_name='borderrouterinterface',
            old_name='port',
            new_name='internal_addr_idx',
        ),
        migrations.RenameField(
            model_name='borderrouterinterface',
            old_name='remote_port',
            new_name='remote_l4port',
        ),
        migrations.RemoveField(
            model_name='borderrouteraddress',
            name='port',
        ),
        migrations.RemoveField(
            model_name='serviceaddress',
            name='port',
        ),
        migrations.AddField(
            model_name='borderrouteraddress',
            name='l4port',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='borderrouterinterface',
            name='l4port',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='serviceaddress',
            name='l4port',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='borderrouteraddress',
            name='addr_type',
            field=models.CharField(max_length=5, default='IPv4'),
        ),
        migrations.AlterField(
            model_name='serviceaddress',
            name='addr_type',
            field=models.CharField(max_length=5, default='IPv4'),
        ),
    ]
