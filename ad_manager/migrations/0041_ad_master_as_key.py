# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0040_auto_20170224_1319'),
    ]

    operations = [
        migrations.AddField(
            model_name='ad',
            name='master_as_key',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
