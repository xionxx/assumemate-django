# Generated by Django 5.1.1 on 2024-11-04 08:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='listingapplication',
            name='user_id',
        ),
        migrations.AlterField(
            model_name='listingapplication',
            name='list_app_status',
            field=models.CharField(default='PENDING', max_length=20),
        ),
    ]