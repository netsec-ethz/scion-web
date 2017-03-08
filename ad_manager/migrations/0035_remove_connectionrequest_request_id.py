# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0034_auto_20161209_1538'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='connectionrequest',
            name='request_id',
        ),
    ]
