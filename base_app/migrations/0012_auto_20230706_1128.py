# Generated by Django 4.2.1 on 2023-07-06 11:28

from django.db import migrations

def remove_save_from_ClientDataCollectionPool(apps, schema_editor):
    ClientDataCollectionPool = apps.get_model('base_app', 'ClientDataCollectionPool')
    ClientDataCollectionPool.save = None

class Migration(migrations.Migration):

    dependencies = [
        ('base_app', '0011_remove_patientappointment_patient_id_and_more'),
    ]

    operations = [
        migrations.RunPython(remove_save_from_ClientDataCollectionPool),
    ]



