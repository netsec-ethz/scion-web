# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0037_auto_20170207_1556'),
    ]

    operations = [
        migrations.AlterField(
            model_name='routerweb',
            name='interface_port',
            field=models.IntegerField(),
        ),
        migrations.AlterField(
            model_name='routerweb',
            name='interface_toaddr',
            field=models.GenericIPAddressField(null=True),
        ),
        migrations.AlterField(
            model_name='routerweb',
            name='interface_toport',
            field=models.IntegerField(null=True),
        ),
    ]
