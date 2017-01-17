# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


def set_defaults(apps, schema_editor):
    models = ['BeaconServerWeb', 'CertificateServerWeb', 'PathServerWeb',
              'RouterWeb', 'SibraServerWeb']
    for model in models:
        model_obj = apps.get_model("ad_manager", model)
        set(model_obj)


def set(service):
    for instance in service.objects.all():
        instance.port = 0
        instance.save()


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0042_merge'),
    ]

    operations = [
        migrations.AlterField(
            model_name='beaconserverweb',
            name='port',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='certificateserverweb',
            name='port',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='pathserverweb',
            name='port',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='routerweb',
            name='port',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='sibraserverweb',
            name='port',
            field=models.IntegerField(null=True),
        ),
        migrations.RunPython(set_defaults),
        migrations.AlterField(
            model_name='beaconserverweb',
            name='port',
            field=models.IntegerField(),
        ),
        migrations.AlterField(
            model_name='certificateserverweb',
            name='port',
            field=models.IntegerField(),
        ),
        migrations.AlterField(
            model_name='pathserverweb',
            name='port',
            field=models.IntegerField(),
        ),
        migrations.AlterField(
            model_name='routerweb',
            name='port',
            field=models.IntegerField(),
        ),
        migrations.AlterField(
            model_name='sibraserverweb',
            name='port',
            field=models.IntegerField(),
        ),
    ]
