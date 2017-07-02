# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0046_auto_20170406_0908'),
    ]

    operations = [
        migrations.CreateModel(
            name='BorderRouter',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, serialize=False, auto_created=True)),
                ('name', models.CharField(null=True, max_length=20)),
                ('ad', models.ForeignKey(to='ad_manager.AD')),
            ],
        ),
        migrations.CreateModel(
            name='BorderRouterAddress',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, serialize=False, auto_created=True)),
                ('addr', models.GenericIPAddressField()),
                ('l4port', models.IntegerField(default=-1)),
                ('overlay_port', models.IntegerField(null=True)),
                ('addr_type', models.CharField(default='IPv4', max_length=5)),
                ('is_public', models.BooleanField(default=True)),
                ('ad', models.ForeignKey(to='ad_manager.AD')),
                ('router', models.ForeignKey(to='ad_manager.BorderRouter')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='BorderRouterInterface',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, serialize=False, auto_created=True)),
                ('addr', models.GenericIPAddressField()),
                ('l4port', models.IntegerField(default=-1)),
                ('bind_addr', models.GenericIPAddressField(null=True, default=None)),
                ('bind_l4port', models.IntegerField(null=True, default=None)),
                ('remote_addr', models.GenericIPAddressField(null=True)),
                ('remote_l4port', models.IntegerField(null=True)),
                ('internal_addr_idx', models.IntegerField()),
                ('interface_id', models.IntegerField()),
                ('bandwidth', models.IntegerField()),
                ('mtu', models.IntegerField()),
                ('neighbor_isd_id', models.IntegerField(null=True)),
                ('neighbor_as_id', models.IntegerField(null=True)),
                ('neighbor_type', models.CharField(max_length=10, choices=[('CHILD', 'CHILD'), ('PARENT', 'PARENT'), ('PEER', 'PEER'), ('CORE', 'CORE')])),
                ('ad', models.ForeignKey(to='ad_manager.AD')),
                ('router_addr', models.ForeignKey(to='ad_manager.BorderRouterAddress')),
            ],
        ),
        migrations.CreateModel(
            name='Service',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, serialize=False, auto_created=True)),
                ('name', models.CharField(null=True, max_length=20)),
                ('ad', models.ForeignKey(to='ad_manager.AD')),
            ],
        ),
        migrations.CreateModel(
            name='ServiceAddress',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, serialize=False, auto_created=True)),
                ('addr', models.GenericIPAddressField()),
                ('l4port', models.IntegerField(default=-1)),
                ('overlay_port', models.IntegerField(null=True)),
                ('addr_type', models.CharField(default='IPv4', max_length=5)),
                ('is_public', models.BooleanField(default=True)),
                ('ad', models.ForeignKey(to='ad_manager.AD')),
                ('service', models.ForeignKey(to='ad_manager.Service')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
