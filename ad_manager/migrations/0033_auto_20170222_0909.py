# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0032_auto_20161109_1632'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='routerweb',
            unique_together=set([('ad', 'addr', 'interface_port')]),
        ),
    ]
