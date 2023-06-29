# Generated by Django 4.2.1 on 2023-06-28 09:57

import base_app.models
from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import django_resized.forms
import phonenumber_field.modelfields


class Migration(migrations.Migration):

    dependencies = [
        ('base_app', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ClientDataCollectionPool',
            fields=[
                ('client_id', models.CharField(editable=False, max_length=50, primary_key=True, serialize=False, unique=True)),
                ('client_first_name', models.CharField(blank=True, max_length=250, null=True)),
                ('client_last_name', models.CharField(blank=True, max_length=250, null=True)),
                ('client_dob', models.CharField(blank=True, max_length=250, null=True)),
                ('client_gender', models.CharField(blank=True, max_length=250, null=True)),
                ('client_contact_number', models.CharField(blank=True, max_length=250, null=True)),
                ('client_email', models.CharField(blank=True, max_length=250, null=True)),
                ('client_billing_address', models.CharField(blank=True, max_length=250, null=True)),
                ('appointment_count', models.IntegerField(default=0)),
                ('prescription_count', models.IntegerField(default=0)),
                ('total_billings', models.IntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='ClientPaymentData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('session_id', models.CharField(max_length=250)),
                ('payment_intent', models.CharField(blank=True, max_length=250, null=True)),
                ('payment_method', models.CharField(blank=True, max_length=250, null=True)),
                ('client_billing_address', models.CharField(blank=True, max_length=250, null=True)),
                ('stripe_session_status', models.CharField(blank=True, max_length=250, null=True)),
                ('stripe_payment_status', models.CharField(blank=True, max_length=250, null=True)),
                ('session_created_on', models.CharField(blank=True, max_length=250, null=True)),
                ('session_expired_on', models.CharField(blank=True, max_length=250, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='MedicalProceduresTypes',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('procedure_choice', models.CharField(choices=[('MEDICAL_EXAMINATION', 'Medical Examination'), ('ROUTINE_CHECK_UP', 'Routine Check-up'), ('RESULT_ANALYSIS', 'Result Analysis'), ('BLOOD_TESTS', 'Blood Tests'), ('X_RAY', 'X-ray'), ('ULTRASOUND', 'Ultrasound'), ('VACCINATIONS', 'Vaccinations'), ('BIOPSY', 'Biopsy'), ('SURGERY', 'Surgery'), ('PHYSICAL_THERAPY', 'Physical Therapy'), ('HEARING_TEST', 'Hearing Test'), ('VISION_TEST', 'Vision Test'), ('CARDIAC_STRESS_TEST', 'Cardiac Stress Test'), ('ORGAN_DONATION', 'Organ Donation'), ('CONSULTATION', 'Consultation'), ('OTHER', 'Other')], default='OTHER', max_length=154, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='PharmacyInventory',
            fields=[
                ('drug_id', models.CharField(editable=False, max_length=50, primary_key=True, serialize=False, unique=True)),
                ('stripe_product_id', models.CharField(blank=True, editable=False, max_length=255, null=True)),
                ('drug_name', models.CharField(max_length=250, unique=True)),
                ('drug_image', django_resized.forms.ResizedImageField(blank=True, crop=None, default='default_image.png', force_format=None, keep_meta=True, null=True, quality=-1, scale=None, size=[150, 150], upload_to='Drug_Stock_Images')),
                ('generic_name', models.CharField(max_length=250)),
                ('brand_name', models.CharField(max_length=250)),
                ('drug_class', models.CharField(choices=[('ANALGESICS: Used for headaches, muscle pain, toothaches, menstrual pain', 'ANALGESICS'), ('ANTIPYRETICS: Used to reduce fever', 'ANTIPYRETICS'), ('ANTACIDS: Used for heartburn, indigestion, acid reflux', 'ANTACIDS'), ('ANTIHISTAMINES: Used for allergies, itchy skin or eyes, sneezing, runny nose', 'ANTIHISTAMINES'), ('COUGH AND COLD: Used for cough relief, nasal congestion, sore throat', 'COUGH_AND_COLD'), ('TOPICAL ANALGESICS: Used for muscle aches and strains, joint pain, minor injuries', 'TOPICAL_ANALGESICS'), ('ANTIDIARRHEALS: Used for diarrhea relief', 'ANTIDIARRHEALS'), ('DERMATOLOGICAL: Used for acne treatment, eczema or dermatitis management, fungal infections', 'DERMATOLOGICAL'), ('ORAL CONTRACEPTIVES: Used for pregnancy prevention', 'ORAL_CONTRACEPTIVES'), ('OPHTHALMIC: Used for eye infections, dry eyes, allergic conjunctivitis', 'OPHTHALMIC'), ('Other', 'OTHER')], default='Other', max_length=250)),
                ('dosage_form', models.CharField(choices=[('ORAL', 'Oral'), ('OPHTHALMIC', 'Ophthalmic'), ('INHALATION', 'Inhalation'), ('INJECTION', 'Injection'), ('TOPICAL', 'Topical'), ('OTHER', 'Other')], default='OTHER', max_length=250)),
                ('unit_type', models.CharField(choices=[('SINGLE_UNIT', 'Single Unit'), ('PACK_OF_10', 'Pack of 10'), ('PACK_OF_50', 'Pack of 50')], default='SINGLE_UNIT', max_length=250)),
                ('price', models.DecimalField(decimal_places=2, default=0, max_digits=10)),
                ('stripe_price_id', models.CharField(blank=True, editable=False, max_length=255, null=True)),
                ('add_new_stock', models.PositiveIntegerField(default=0, help_text='add_quantity')),
                ('stock_available', models.PositiveIntegerField(default=0, editable=False, help_text='available_stock')),
                ('stock_history', models.TextField(default='[]', editable=False, help_text='stock history')),
                ('manufacture_date', models.DateField(default=django.utils.timezone.now)),
                ('lifetime_in_months', models.PositiveIntegerField(default=0, help_text='number_of_months')),
                ('expiry_date', models.DateField(blank=True, default=None, editable=False, null=True)),
                ('added_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='PrescribedMedicationModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('purpose', models.CharField(blank=True, editable=False, max_length=250, null=True)),
                ('amount_per_unit', models.DecimalField(decimal_places=2, default=0, editable=False, max_digits=10)),
                ('quantity', models.PositiveIntegerField(default=0)),
                ('total_payable_amount', models.DecimalField(decimal_places=2, default=0, editable=False, max_digits=10)),
                ('dosage_freq', models.CharField(choices=[('ONCE_A_DAY', 'Once a day'), ('TWICE_A_DAY', 'Twice a day'), ('THRICE_A_DAY', 'Thrice a day'), ('FLEXIBLE', 'Flexible timings')], default='FLEXIBLE', max_length=250, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Prescription',
            fields=[
                ('prescription_id', models.CharField(editable=False, max_length=50, primary_key=True, serialize=False, unique=True)),
                ('stripe_appointment_service_id', models.CharField(blank=True, max_length=250, null=True)),
                ('stripe_appointment_price_id', models.CharField(blank=True, max_length=250, null=True)),
                ('appointment_fee', models.DecimalField(decimal_places=2, default=0, editable=False, max_digits=10)),
                ('med_bill_amount', models.DecimalField(decimal_places=2, default=0, editable=False, max_digits=10)),
                ('coupon_discount', models.DecimalField(decimal_places=2, default=0, max_digits=10)),
                ('grand_total', models.DecimalField(decimal_places=2, default=0, editable=False, max_digits=10)),
                ('description', models.TextField(blank=True, max_length=300, null=True)),
                ('approval_status', models.CharField(choices=[('APPROVED', 'Approved'), ('PENDING', 'Pending'), ('CANCELLED', 'Cancelled')], default='PENDING', max_length=100)),
                ('payment_status', models.CharField(default='UNPAID', max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
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
            model_name='patientappointment',
            old_name='email',
            new_name='patient_email',
        ),
        migrations.RemoveField(
            model_name='clinic',
            name='address',
        ),
        migrations.RemoveField(
            model_name='clinic',
            name='clinic_url',
        ),
        migrations.RemoveField(
            model_name='clinic',
            name='mobile_number',
        ),
        migrations.RemoveField(
            model_name='clinic',
            name='status',
        ),
        migrations.RemoveField(
            model_name='clinicmember',
            name='status',
        ),
        migrations.RemoveField(
            model_name='patientappointment',
            name='contact_number',
        ),
        migrations.RemoveField(
            model_name='patientappointment',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='patientappointment',
            name='department',
        ),
        migrations.AddField(
            model_name='clinic',
            name='clinic_address',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
        migrations.AddField(
            model_name='clinic',
            name='clinic_city',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='clinic',
            name='clinic_contact_number',
            field=phonenumber_field.modelfields.PhoneNumberField(blank=True, default=None, max_length=128, null=True, region=None, validators=[django.core.validators.RegexValidator('^(\\+\\d{1,3})?,?\\s?\\d{8,15}')]),
        ),
        migrations.AddField(
            model_name='clinic',
            name='clinic_logo',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, default='avatar.jpg', force_format=None, keep_meta=True, null=True, quality=-1, scale=None, size=[150, 150], upload_to='profile_avatars'),
        ),
        migrations.AddField(
            model_name='clinic',
            name='clinic_status',
            field=models.CharField(choices=[('APPROVED', 'Approved'), ('PENDING', 'Pending'), ('CANCELLED', 'Cancelled')], default='PENDING', max_length=100),
        ),
        migrations.AddField(
            model_name='clinic',
            name='clinic_zipcode',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='clinicmember',
            name='shift_type',
            field=models.CharField(choices=[('General Shift 9AM - 6PM', '09:00 AM - 06:00 PM'), ('Flex Shift 10AM - 2PM', '10:00 AM - 02:00 PM'), ('Flex Shift 3PM - 7PM', '03:00 PM - 07:00 PM'), ('Front Line Shift 7AM - 7PM', '07:00 AM - 07:00 PM'), ('Front Line Shift 7PM - 7AM', '07:00 PM - 07:00 AM')], default='General Shift 9AM - 6PM', max_length=100),
        ),
        migrations.AddField(
            model_name='clinicmember',
            name='staff_avatar',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, default='avatar.jpg', force_format=None, keep_meta=True, null=True, quality=-1, scale=None, size=[150, 150], upload_to='profile_avatars'),
        ),
        migrations.AddField(
            model_name='clinicmember',
            name='staff_contact_number',
            field=phonenumber_field.modelfields.PhoneNumberField(blank=True, default=None, max_length=128, null=True, region=None, validators=[django.core.validators.RegexValidator('^(\\+\\d{1,3})?,?\\s?\\d{8,15}')]),
        ),
        migrations.AddField(
            model_name='clinicmember',
            name='staff_status',
            field=models.CharField(choices=[('APPROVED', 'Approved'), ('PENDING', 'Pending'), ('CANCELLED', 'Cancelled')], default='PENDING', max_length=100),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='appointment_description',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='appointment_status',
            field=models.CharField(choices=[('APPROVED', 'Approved'), ('PENDING', 'Pending'), ('CANCELLED', 'Cancelled')], default='PENDING', max_length=100),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='clinic_name',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='main_clinic_name', to='base_app.clinic'),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='date_of_birth',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='last_updated',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='patient_age',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='patient_contact_number',
            field=phonenumber_field.modelfields.PhoneNumberField(blank=True, default=None, max_length=128, null=True, region=None, validators=[django.core.validators.RegexValidator('^(\\+\\d{1,3})?,?\\s?\\d{8,15}')]),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='patient_gender',
            field=models.CharField(choices=[('MALE', 'Male'), ('FEMALE', 'Female'), ('UNDISCLOSED', 'Undisclosed')], default=None, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='recurring_patient',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='relatedDepartment',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='relatedRecipient',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='recipient_name', to='base_app.clinicmember'),
        ),
        migrations.AlterField(
            model_name='clinic',
            name='clinic_id',
            field=models.CharField(editable=False, max_length=50, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='clinic',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='clinicmember',
            name='clinic_name',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='base_app.clinic'),
        ),
        migrations.AlterField(
            model_name='clinicmember',
            name='staff_id',
            field=models.CharField(editable=False, max_length=50, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='avatar',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, default='avatar.jpg', force_format=None, keep_meta=True, null=True, quality=-1, scale=None, size=[150, 150], upload_to='profile_avatars'),
        ),
        migrations.AlterField(
            model_name='patientappointment',
            name='appointment_date',
            field=models.DateField(default=django.utils.timezone.now, validators=[base_app.models.PatientAppointment.validate_date, base_app.models.PatientAppointment.validate_weekday]),
        ),
        migrations.AlterField(
            model_name='patientappointment',
            name='appointment_id',
            field=models.CharField(editable=False, max_length=50, primary_key=True, serialize=False, unique=True),
        ),
        migrations.DeleteModel(
            name='Drug',
        ),
        migrations.AddField(
            model_name='prescription',
            name='appointment_id',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='prescriptions', to='base_app.patientappointment'),
        ),
        migrations.AddField(
            model_name='prescription',
            name='clinic_name',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='prescriptions', to='base_app.clinic'),
        ),
        migrations.AddField(
            model_name='prescription',
            name='consultant',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='prescriptions', to='base_app.clinicmember'),
        ),
        migrations.AddField(
            model_name='prescription',
            name='medications',
            field=models.ManyToManyField(related_name='prescriptions', to='base_app.prescribedmedicationmodel'),
        ),
        migrations.AddField(
            model_name='prescribedmedicationmodel',
            name='for_prescription',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='base_app.prescription'),
        ),
        migrations.AddField(
            model_name='prescribedmedicationmodel',
            name='medicine',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='base_app.pharmacyinventory'),
        ),
        migrations.AddField(
            model_name='clientpaymentdata',
            name='prescription_id',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='prescription_receipt_id', to='base_app.prescription'),
        ),
        migrations.AddField(
            model_name='patientappointment',
            name='procedures',
            field=models.ManyToManyField(to='base_app.medicalprocedurestypes'),
        ),
    ]
