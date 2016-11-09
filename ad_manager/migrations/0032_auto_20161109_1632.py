# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0031_auto_20161020_1319'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='ad',
            options={'verbose_name': 'AD', 'ordering': ['as_id']},
        ),
        migrations.AlterUniqueTogether(
            name='ad',
            unique_together=set([('as_id', 'isd')]),
        ),
    ]
