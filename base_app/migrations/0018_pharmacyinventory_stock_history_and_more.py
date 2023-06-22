# Generated by Django 4.2.1 on 2023-06-21 06:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base_app', '0017_alter_pharmacyinventory_unit_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='pharmacyinventory',
            name='stock_history',
            field=models.TextField(default='[]', editable=False, help_text='stock history'),
        ),
        migrations.AddField(
            model_name='prescription',
            name='appointment_fee',
            field=models.DecimalField(decimal_places=2, default=0, editable=False, max_digits=10),
        ),
        migrations.AddField(
            model_name='prescription',
            name='stripe_appointment_price_d',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
        migrations.AddField(
            model_name='prescription',
            name='stripe_appointment_service_id',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
        migrations.AlterField(
            model_name='pharmacyinventory',
            name='stock_available',
            field=models.PositiveIntegerField(default=0, editable=False, help_text='available_stock'),
        ),
    ]
