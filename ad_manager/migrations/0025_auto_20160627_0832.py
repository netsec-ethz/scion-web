# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0024_auto_20160620_1831'),
    ]

    operations = [
        migrations.CreateModel(
            name='SibraServerWeb',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True, serialize=False)),
                ('addr', models.GenericIPAddressField()),
                ('name', models.CharField(max_length=20, null=True)),
                ('ad', models.ForeignKey(to='ad_manager.AD')),
            ],
            options={
                'verbose_name': 'SIBRA server',
            },
            bases=(models.Model,),
        ),
        migrations.AlterUniqueTogether(
            name='sibraserverweb',
            unique_together=set([('ad', 'addr')]),
        ),
    ]
