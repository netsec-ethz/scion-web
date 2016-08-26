# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0025_auto_20160627_0832'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='dnsserverweb',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='dnsserverweb',
            name='ad',
        ),
        migrations.DeleteModel(
            name='DnsServerWeb',
        ),
        migrations.DeleteModel(
            name='Node',
        ),
        migrations.DeleteModel(
            name='PackageVersion',
        ),
        migrations.RemoveField(
            model_name='ad',
            name='dns_domain',
        ),
        migrations.AlterField(
            model_name='ad',
            name='md_host',
            field=models.GenericIPAddressField(default='127.0.0.1'),
            preserve_default=True,
        ),
    ]
