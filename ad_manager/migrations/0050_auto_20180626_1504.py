# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0049_auto_20180222_1931'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='ad',
            options={'verbose_name': 'AD', 'ordering': ['as_id_str']},
        ),
        migrations.AddField(
            model_name='ad',
            name='as_id_str',
            field=models.CharField(max_length=15, null=True),
        ),
        migrations.AddField(
            model_name='borderrouterinterface',
            name='neighbor_as_id_str',
            field=models.CharField(max_length=15, null=True),
        ),
    ]
