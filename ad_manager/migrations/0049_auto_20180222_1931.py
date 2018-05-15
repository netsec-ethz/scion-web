# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import ad_manager.util.common
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0048_auto_20170706_1524'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='sibraserverweb',
            unique_together=set([]),
        ),
        migrations.RemoveField(
            model_name='sibraserverweb',
            name='ad',
        ),
        migrations.AddField(
            model_name='ad',
            name='core_keys',
            field=jsonfield.fields.JSONField(default=ad_manager.util.common.empty_dict),
        ),
        migrations.AddField(
            model_name='ad',
            name='keys',
            field=jsonfield.fields.JSONField(default=ad_manager.util.common.empty_dict),
        ),
        migrations.DeleteModel(
            name='SibraServerWeb',
        ),
    ]
