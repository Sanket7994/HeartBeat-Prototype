# Generated by Django 4.2.1 on 2023-06-17 11:14

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('base_app', '0008_alter_prescribedmedication_medicine'),
    ]

    operations = [
        migrations.AddField(
            model_name='prescribedmedication',
            name='for_prescription',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='base_app.prescription'),
        ),
    ]
