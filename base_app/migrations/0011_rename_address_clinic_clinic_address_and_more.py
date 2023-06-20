# Generated by Django 4.2.1 on 2023-06-19 08:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base_app', '0010_medicalprocedurestypes_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='clinic',
            old_name='address',
            new_name='clinic_address',
        ),
        migrations.RenameField(
            model_name='clinic',
            old_name='city',
            new_name='clinic_city',
        ),
        migrations.RenameField(
            model_name='clinic',
            old_name='contact_number',
            new_name='clinic_contact_number',
        ),
        migrations.RenameField(
            model_name='clinic',
            old_name='country',
            new_name='clinic_country',
        ),
        migrations.RenameField(
            model_name='clinic',
            old_name='email',
            new_name='clinic_email',
        ),
        migrations.RenameField(
            model_name='clinic',
            old_name='avatar',
            new_name='clinic_logo',
        ),
        migrations.RenameField(
            model_name='clinic',
            old_name='status',
            new_name='clinic_status',
        ),
        migrations.RenameField(
            model_name='clinic',
            old_name='zipcode',
            new_name='clinic_zipcode',
        ),
        migrations.RenameField(
            model_name='clinicmember',
            old_name='avatar',
            new_name='staff_avatar',
        ),
        migrations.RenameField(
            model_name='clinicmember',
            old_name='contact_number',
            new_name='staff_contact_number',
        ),
        migrations.RenameField(
            model_name='clinicmember',
            old_name='designation',
            new_name='staff_designation',
        ),
        migrations.RenameField(
            model_name='clinicmember',
            old_name='email',
            new_name='staff_email',
        ),
        migrations.RenameField(
            model_name='clinicmember',
            old_name='first_name',
            new_name='staff_first_name',
        ),
        migrations.RenameField(
            model_name='clinicmember',
            old_name='last_name',
            new_name='staff_last_name',
        ),
        migrations.RenameField(
            model_name='clinicmember',
            old_name='status',
            new_name='staff_status',
        ),
        migrations.RenameField(
            model_name='patientappointment',
            old_name='status',
            new_name='appointment_status',
        ),
        migrations.RenameField(
            model_name='patientappointment',
            old_name='contact_number',
            new_name='patient_contact_number',
        ),
        migrations.RenameField(
            model_name='patientappointment',
            old_name='email',
            new_name='patient_email',
        ),
        migrations.RenameField(
            model_name='patientappointment',
            old_name='gender',
            new_name='patient_gender',
        ),
        migrations.AddField(
            model_name='prescribedmedication',
            name='amount_per_unit',
            field=models.DecimalField(decimal_places=2, default=0, max_digits=10),
        ),
        migrations.AddField(
            model_name='prescribedmedication',
            name='purpose',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
        migrations.AddField(
            model_name='prescription',
            name='bill_amount',
            field=models.DecimalField(decimal_places=2, default=0, max_digits=10),
        ),
    ]
