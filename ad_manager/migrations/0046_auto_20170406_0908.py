# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0045_routerweb_remove_foreignkey_20170313_1439'),
    ]

    operations = [
        migrations.AddField(
            model_name='ad',
            name='simple_conf_mode',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='connectionrequest',
            name='link_type',
            field=models.CharField(max_length=20, choices=[('PARENT', 'PARENT'), ('CHILD', 'CHILD'), ('PEER', 'PEER'), ('CORE', 'CORE')], default='PARENT'),
        ),
    ]
