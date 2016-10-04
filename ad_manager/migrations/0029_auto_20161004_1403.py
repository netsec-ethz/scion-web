# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0028_auto_20161004_1139'),
    ]

    operations = [
        migrations.RenameField(
            model_name='connectionrequest',
            old_name='new_ad',
            new_name='connect_from',
        ),
        migrations.AddField(
            model_name='connectionrequest',
            name='request_id',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='connectionrequest',
            name='mtu',
            field=models.IntegerField(null=True, default=1472),
        ),
    ]
