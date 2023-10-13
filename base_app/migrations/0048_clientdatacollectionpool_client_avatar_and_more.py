# Generated by Django 4.2.1 on 2023-08-25 10:50

import datetime
from django.db import migrations, models
import django_resized.forms


class Migration(migrations.Migration):

    dependencies = [
        ('base_app', '0047_remove_financialdataevaluation_department_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='clientdatacollectionpool',
            name='client_avatar',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, force_format=None, keep_meta=True, null=True, quality=-1, scale=None, size=[150, 150], upload_to='profile_avatars'),
        ),
        migrations.AddField(
            model_name='clinicmember',
            name='staff_fixed_salary',
            field=models.DecimalField(decimal_places=2, default=0, max_digits=10),
        ),
        migrations.AlterField(
            model_name='financialdataevaluation',
            name='end_date',
            field=models.DateField(default=datetime.datetime(2023, 9, 23, 10, 50, 27, 435399, tzinfo=datetime.timezone.utc)),
        ),
    ]
