# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0036_joinrequest_join_as_a_core'),
    ]

    operations = [
        migrations.RenameField(
            model_name='organisationadmin',
            old_name='key',
            new_name='account_id',
        ),
    ]
