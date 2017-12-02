# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0047_borderrouter_borderrouteraddress_borderrouterinterface_service_serviceaddress'),
    ]

    operations = [
        migrations.CreateModel(
            name='CloudMachine',
            fields=[
                ('id', models.AutoField(auto_created=True, verbose_name='ID', primary_key=True, serialize=False)),
                ('addr', models.GenericIPAddressField()),
                ('host_name', models.CharField(max_length=20, null=True)),
                ('cloud_provider', models.CharField(max_length=20, null=True)),
            ],
        ),
        migrations.AddField(
            model_name='ad',
            name='commit_hash',
            field=models.CharField(max_length=100, default=''),
        ),
        migrations.AddField(
            model_name='cloudmachine',
            name='ad',
            field=models.ForeignKey(to='ad_manager.AD'),
        ),
    ]
