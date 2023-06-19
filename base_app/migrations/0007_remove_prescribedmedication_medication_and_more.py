# Generated by Django 4.2.1 on 2023-06-16 10:08

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('base_app', '0006_remove_prescription_dosage_freq_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='prescribedmedication',
            name='medication',
        ),
        migrations.AddField(
            model_name='prescribedmedication',
            name='medicine',
            field=models.OneToOneField(null=True, on_delete=django.db.models.deletion.SET_NULL, to='base_app.pharmacyinventory'),
        ),
        migrations.AlterField(
            model_name='prescription',
            name='prescription_id',
            field=models.CharField(editable=False, max_length=50, primary_key=True, serialize=False, unique=True),
        ),
    ]
