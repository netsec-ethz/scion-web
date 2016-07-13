# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0025_auto_20160627_0832'),
    ]

    operations = [
        migrations.AddField(
            model_name='ad',
            name='certificate',
            field=models.CharField(blank=True, max_length=100, null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='ad',
            name='enc_priv_key',
            field=models.CharField(blank=True, max_length=100, null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='ad',
            name='enc_pub_key',
            field=models.CharField(blank=True, max_length=100, null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='ad',
            name='sig_priv_key',
            field=models.CharField(blank=True, max_length=100, null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='ad',
            name='sig_pub_key',
            field=models.CharField(blank=True, max_length=100, null=True),
            preserve_default=True,
        ),
    ]
