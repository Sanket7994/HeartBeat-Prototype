# Generated by Django 4.2.1 on 2023-06-16 08:55

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('base_app', '0004_pharmacyinventory_prescribedmedication_and_more'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='prescribedmedication',
            name='once_per_medication_prescription',
        ),
        migrations.RemoveField(
            model_name='prescribedmedication',
            name='prescription',
        ),
    ]
