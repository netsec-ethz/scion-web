# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0032_auto_20161109_1632'),
    ]

    operations = [
        migrations.AddField(
            model_name='beaconserverweb',
            name='port',
            field=models.IntegerField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='certificateserverweb',
            name='port',
            field=models.IntegerField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='pathserverweb',
            name='port',
            field=models.IntegerField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='routerweb',
            name='port',
            field=models.IntegerField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='sibraserverweb',
            name='port',
            field=models.IntegerField(default=None, null=True),
        ),
        migrations.AlterUniqueTogether(
            name='beaconserverweb',
            unique_together=set([('ad', 'addr', 'port')]),
        ),
        migrations.AlterUniqueTogether(
            name='certificateserverweb',
            unique_together=set([('ad', 'addr', 'port')]),
        ),
        migrations.AlterUniqueTogether(
            name='pathserverweb',
            unique_together=set([('ad', 'addr', 'port')]),
        ),
        migrations.AlterUniqueTogether(
            name='routerweb',
            unique_together=set([('ad', 'addr', 'port')]),
        ),
        migrations.AlterUniqueTogether(
            name='sibraserverweb',
            unique_together=set([('ad', 'addr', 'port')]),
        ),
    ]
