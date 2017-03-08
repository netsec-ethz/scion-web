# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0039_connectionrequest_router_info'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ad',
            name='certificate',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='ad',
            name='trc',
            field=models.TextField(blank=True, null=True),
        ),
    ]
