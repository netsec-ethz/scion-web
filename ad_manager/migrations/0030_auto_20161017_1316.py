# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0029_auto_20161004_1403'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='joinrequest',
            name='core_as_signing',
        ),
        migrations.RemoveField(
            model_name='joinrequest',
            name='join_isd',
        ),
        migrations.AddField(
            model_name='joinrequest',
            name='isd_to_join',
            field=models.IntegerField(default=-1),
        ),
    ]
