# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('ad_manager', '0026_auto_20160823_1558'),
    ]

    operations = [
        migrations.CreateModel(
            name='JoinRequest',
            fields=[
                ('request_id', models.IntegerField(serialize=False, primary_key=True)),
                ('core_as_signing', models.CharField(null=True, max_length=10)),
                ('status', models.CharField(default='NONE', choices=[('NONE', 'NONE'), ('SENT', 'SENT'), ('ACCEPTED', 'ACCEPTED'), ('DECLINED', 'DECLINED')], max_length=20)),
                ('sig_pub_key', models.CharField(blank=True, max_length=100, null=True)),
                ('sig_priv_key', models.CharField(blank=True, max_length=100, null=True)),
                ('enc_pub_key', models.CharField(blank=True, max_length=100, null=True)),
                ('enc_priv_key', models.CharField(blank=True, max_length=100, null=True)),
                ('certificate', models.CharField(blank=True, max_length=1000, null=True)),
                ('trc', models.CharField(blank=True, max_length=500, null=True)),
                ('created_by', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
                ('join_isd', models.ForeignKey(to='ad_manager.ISD')),
            ],
        ),
        migrations.CreateModel(
            name='OrganisationAdmin',
            fields=[
                ('id', models.AutoField(serialize=False, verbose_name='ID', auto_created=True, primary_key=True)),
                ('is_org_admin', models.BooleanField(default=False)),
                ('key', models.CharField(blank=True, max_length=260)),
                ('secret', models.CharField(blank=True, max_length=260)),
                ('user', models.OneToOneField(to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.RenameField(
            model_name='connectionrequest',
            old_name='new_ad',
            new_name='connect_from',
        ),
        migrations.RemoveField(
            model_name='connectionrequest',
            name='package_path',
        ),
        migrations.AddField(
            model_name='ad',
            name='as_id',
            field=models.IntegerField(default=1),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='ad',
            name='certificate',
            field=models.CharField(blank=True, max_length=1000, null=True),
        ),
        migrations.AddField(
            model_name='ad',
            name='enc_priv_key',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='ad',
            name='enc_pub_key',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='ad',
            name='sig_priv_key',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='ad',
            name='sig_pub_key',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='ad',
            name='trc',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AddField(
            model_name='beaconserverweb',
            name='addr_internal',
            field=models.GenericIPAddressField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='beaconserverweb',
            name='port_internal',
            field=models.IntegerField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='certificateserverweb',
            name='addr_internal',
            field=models.GenericIPAddressField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='certificateserverweb',
            name='port_internal',
            field=models.IntegerField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='connectionrequest',
            name='bandwidth',
            field=models.IntegerField(default=1000, null=True),
        ),
        migrations.AddField(
            model_name='connectionrequest',
            name='link_type',
            field=models.CharField(default='CHILD', choices=[('PARENT', 'PARENT'), ('CHILD', 'CHILD'), ('PEER', 'PEER'), ('ROUTING', 'ROUTING')], max_length=20),
        ),
        migrations.AddField(
            model_name='connectionrequest',
            name='mtu',
            field=models.IntegerField(default=1472, null=True),
        ),
        migrations.AddField(
            model_name='connectionrequest',
            name='request_id',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='pathserverweb',
            name='addr_internal',
            field=models.GenericIPAddressField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='pathserverweb',
            name='port_internal',
            field=models.IntegerField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='routerweb',
            name='addr_internal',
            field=models.GenericIPAddressField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='routerweb',
            name='port_internal',
            field=models.IntegerField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='sibraserverweb',
            name='addr_internal',
            field=models.GenericIPAddressField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='sibraserverweb',
            name='port_internal',
            field=models.IntegerField(default=None, null=True),
        ),
        migrations.AlterField(
            model_name='ad',
            name='id',
            field=models.AutoField(serialize=False, verbose_name='ID', auto_created=True, primary_key=True),
        ),
        migrations.AlterField(
            model_name='connectionrequest',
            name='connect_to',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='connectionrequest',
            name='router_public_port',
            field=models.IntegerField(default=31000),
        ),
        migrations.AlterField(
            model_name='routerweb',
            name='interface_port',
            field=models.IntegerField(default=31000),
        ),
        migrations.AlterField(
            model_name='routerweb',
            name='interface_toport',
            field=models.IntegerField(default=31000),
        ),
        migrations.AlterUniqueTogether(
            name='ad',
            unique_together=set([('id', 'isd')]),
        ),
    ]
