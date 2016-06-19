# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0022_ad_original_topology'),
    ]

    operations = [
        migrations.CreateModel(
            name='Node',
            fields=[
                ('uuid', models.CharField(serialize=False, primary_key=True, max_length=100)),
                ('name', models.CharField(max_length=50)),
                ('last_seen', models.DateTimeField()),
                ('IP', models.IPAddressField(default='127.0.0.1')),
                ('ISD', models.CharField(max_length=10)),
                ('AS', models.CharField(max_length=10)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.RemoveField(
            model_name='connectionrequest',
            name='router_bound_ip',
        ),
        migrations.RemoveField(
            model_name='connectionrequest',
            name='router_bound_port',
        ),
        migrations.AlterField(
            model_name='connectionrequest',
            name='router_public_port',
            field=models.IntegerField(default=50000, null=True, blank=True),
            preserve_default=True,
        ),
    ]
