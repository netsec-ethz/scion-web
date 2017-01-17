# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0032_auto_20161109_1632'),
    ]

    operations = [
        migrations.AddField(
            model_name='connectionrequest',
            name='overlay_type',
            field=models.CharField(default='UDP/IP', choices=[('IP', 'IP'), ('UDP/IP', 'UDP/IP')], max_length=20),
        ),
    ]
