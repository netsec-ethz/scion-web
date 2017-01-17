# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0033_connectionrequest_overlay_type'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='joinrequest',
            name='request_id',
        ),
        migrations.AddField(
            model_name='joinrequest',
            name='id',
            field=models.AutoField(primary_key=True, auto_created=True, serialize=False, verbose_name='ID', default=0),
            preserve_default=False,
        ),
    ]
