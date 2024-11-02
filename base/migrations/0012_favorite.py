# Generated by Django 5.1.1 on 2024-10-24 14:15

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0011_listingapplication_promotelisting_report_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Favorite',
            fields=[
                ('fav_id', models.BigAutoField(editable=False, primary_key=True, serialize=False)),
                ('fav_date', models.DateTimeField(auto_now_add=True)),
                ('list_id', models.ForeignKey(db_column='list_id', on_delete=django.db.models.deletion.CASCADE, to='base.listing')),
                ('user_id', models.ForeignKey(db_column='user_id', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'favorite',
                'unique_together': {('list_id', 'user_id')},
            },
        ),
    ]