# Generated by Django 5.1.1 on 2024-10-03 11:44

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0003_remove_offer_assumee_id_offer_offer_created_at_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='offer',
            name='list_id',
            field=models.ForeignKey(db_column='list_id', null=True, on_delete=django.db.models.deletion.CASCADE, to='base.listing'),
        ),
    ]