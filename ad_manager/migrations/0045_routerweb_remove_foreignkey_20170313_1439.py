# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


def copy_data(apps, schema_editor):
    model_obj = apps.get_model("ad_manager", "RouterWeb")
    for router in model_obj.objects.all():
        router.neighbor_isd_id = router.neighbor_ad.isd_id
        router.neighbor_as_id = router.neighbor_ad.as_id
        router.save()


class Migration(migrations.Migration):

    dependencies = [
        ('ad_manager', '0044_auto_20170302_1940'),
    ]

    operations = [
        migrations.AddField(
            model_name='routerweb',
            name='neighbor_as_id',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='routerweb',
            name='neighbor_isd_id',
            field=models.IntegerField(null=True),
        ),
        migrations.RunPython(copy_data),
        migrations.RemoveField(
            model_name='routerweb',
            name='neighbor_ad',
        ),
    ]
