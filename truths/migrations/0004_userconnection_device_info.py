# Generated by Django 2.2.4 on 2023-04-17 02:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('truths', '0003_auto_20230412_1720'),
    ]

    operations = [
        migrations.AddField(
            model_name='userconnection',
            name='device_info',
            field=models.TextField(null=True),
        ),
    ]
