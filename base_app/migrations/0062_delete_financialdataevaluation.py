# Generated by Django 4.2.1 on 2023-09-21 17:20

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('base_app', '0061_financialbudget_evaluation_status_and_more'),
    ]

    operations = [
        migrations.DeleteModel(
            name='FinancialDataEvaluation',
        ),
    ]
