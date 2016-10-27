# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0030_auto_20161017_1316'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ad',
            name='certificate',
            field=models.CharField(max_length=1500, blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='ad',
            name='trc',
            field=models.CharField(max_length=1500, blank=True, null=True),
        ),
    ]
