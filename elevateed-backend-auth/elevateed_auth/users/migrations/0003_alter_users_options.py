# Generated by Django 5.1.6 on 2025-02-20 07:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_rename_customuser_users'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='users',
            options={'managed': False},
        ),
    ]
