# Generated by Django 4.2.1 on 2023-08-29 05:28

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base_app', '0050_remove_financialdataevaluation_margin_rate_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='patientappointment',
            name='total_procedure_cost',
            field=models.DecimalField(decimal_places=2, default=0, max_digits=10),
        ),
        migrations.AlterField(
            model_name='clinicmember',
            name='staff_gender',
            field=models.CharField(blank=True, choices=[('MALE', 'Male'), ('FEMALE', 'Female'), ('UNDISCLOSED', 'Undisclosed')], default=None, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='financialdataevaluation',
            name='appointment_income',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
        migrations.AlterField(
            model_name='financialdataevaluation',
            name='donation',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
        migrations.AlterField(
            model_name='financialdataevaluation',
            name='end_date',
            field=models.DateField(default=datetime.datetime(2023, 9, 27, 5, 28, 13, 293213)),
        ),
        migrations.AlterField(
            model_name='financialdataevaluation',
            name='facility_costs',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
        migrations.AlterField(
            model_name='financialdataevaluation',
            name='medical_supplies',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
        migrations.AlterField(
            model_name='financialdataevaluation',
            name='misc_expenses',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
        migrations.AlterField(
            model_name='financialdataevaluation',
            name='monthly_fixed_budget',
            field=models.DecimalField(decimal_places=2, default=150000, max_digits=10),
        ),
        migrations.AlterField(
            model_name='financialdataevaluation',
            name='online_consultation',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
        migrations.AlterField(
            model_name='financialdataevaluation',
            name='prescription_income',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
        migrations.AlterField(
            model_name='financialdataevaluation',
            name='total_employee_salary_amount',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
    ]
