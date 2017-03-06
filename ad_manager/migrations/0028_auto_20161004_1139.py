# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('ad_manager', '0027_auto_20160912_0941'),
    ]

    operations = [
        migrations.CreateModel(
            name='JoinRequest',
            fields=[
                ('request_id', models.IntegerField(serialize=False, primary_key=True)),
                ('core_as_signing', models.CharField(null=True, max_length=10)),
                ('status', models.CharField(default='NONE', max_length=20, choices=[('NONE', 'NONE'), ('SENT', 'SENT'), ('ACCEPTED', 'ACCEPTED'), ('DECLINED', 'DECLINED')])),
                ('sig_pub_key', models.CharField(blank=True, null=True, max_length=100)),
                ('sig_priv_key', models.CharField(blank=True, null=True, max_length=100)),
                ('enc_pub_key', models.CharField(blank=True, null=True, max_length=100)),
                ('enc_priv_key', models.CharField(blank=True, null=True, max_length=100)),
                ('certificate', models.CharField(blank=True, null=True, max_length=1000)),
                ('trc', models.CharField(blank=True, null=True, max_length=500)),
                ('created_by', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
                ('join_isd', models.ForeignKey(to='ad_manager.ISD')),
            ],
        ),
        migrations.CreateModel(
            name='OrganisationAdmin',
            fields=[
                ('id', models.AutoField(auto_created=True, serialize=False, verbose_name='ID', primary_key=True)),
                ('is_org_admin', models.BooleanField(default=False)),
                ('key', models.CharField(blank=True, max_length=260)),
                ('secret', models.CharField(blank=True, max_length=260)),
                ('user', models.OneToOneField(to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.RemoveField(
            model_name='connectionrequest',
            name='package_path',
        ),
        migrations.AddField(
            model_name='ad',
            name='as_id',
            field=models.IntegerField(default=-1),
        ),
        migrations.AddField(
            model_name='ad',
            name='certificate',
            field=models.CharField(blank=True, null=True, max_length=1000),
        ),
        migrations.AddField(
            model_name='ad',
            name='enc_priv_key',
            field=models.CharField(blank=True, null=True, max_length=100),
        ),
        migrations.AddField(
            model_name='ad',
            name='enc_pub_key',
            field=models.CharField(blank=True, null=True, max_length=100),
        ),
        migrations.AddField(
            model_name='ad',
            name='sig_priv_key',
            field=models.CharField(blank=True, null=True, max_length=100),
        ),
        migrations.AddField(
            model_name='ad',
            name='sig_pub_key',
            field=models.CharField(blank=True, null=True, max_length=100),
        ),
        migrations.AddField(
            model_name='ad',
            name='trc',
            field=models.CharField(blank=True, null=True, max_length=500),
        ),
        migrations.AddField(
            model_name='connectionrequest',
            name='bandwidth',
            field=models.IntegerField(null=True, default=1000),
        ),
        migrations.AddField(
            model_name='connectionrequest',
            name='link_type',
            field=models.CharField(default='CHILD', max_length=20, choices=[('PARENT', 'PARENT'), ('CHILD', 'CHILD'), ('PEER', 'PEER'), ('CORE', 'CORE')]),
        ),
        migrations.AddField(
            model_name='connectionrequest',
            name='mtu',
            field=models.IntegerField(null=True, default=1400),
        ),
        migrations.AlterField(
            model_name='ad',
            name='id',
            field=models.AutoField(auto_created=True, serialize=False, verbose_name='ID', primary_key=True),
        ),
        migrations.AlterField(
            model_name='connectionrequest',
            name='connect_to',
            field=models.CharField(blank=True, null=True, max_length=100),
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
