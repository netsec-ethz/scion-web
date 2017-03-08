# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0035_remove_connectionrequest_request_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='joinrequest',
            name='join_as_a_core',
            field=models.BooleanField(default=False),
        ),
    ]
