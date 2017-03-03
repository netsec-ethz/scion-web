# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0043_auto_20170302_1452'),
    ]

    operations = [
        migrations.AlterField(
            model_name='connectionrequest',
            name='overlay_type',
            field=models.CharField(max_length=20, default='UDP/IPv4', choices=[('IPv4', 'IPv4'), ('IPv6', 'IPv6'), ('UDP/IPv4', 'UDP/IPv4'), ('UDP/IPv6', 'UDP/IPv6')]),
        ),
    ]
