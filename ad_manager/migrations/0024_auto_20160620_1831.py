# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0023_auto_20160618_2139'),
    ]

    operations = [
        migrations.AlterField(
            model_name='connectionrequest',
            name='router_public_ip',
            field=models.GenericIPAddressField(default='127.0.0.1'),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='connectionrequest',
            name='router_public_port',
            field=models.IntegerField(default=50000),
            preserve_default=True,
        ),
    ]
