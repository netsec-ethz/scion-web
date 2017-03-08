# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0038_auto_20170214_1113'),
    ]

    operations = [
        migrations.AddField(
            model_name='connectionrequest',
            name='router_info',
            field=models.TextField(null=True),
        ),
    ]
