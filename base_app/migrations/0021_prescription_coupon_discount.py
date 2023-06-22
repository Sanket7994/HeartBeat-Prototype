# Generated by Django 4.2.1 on 2023-06-21 09:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base_app', '0020_prescription_approval_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='prescription',
            name='coupon_discount',
            field=models.DecimalField(decimal_places=2, default=0, max_digits=10),
        ),
    ]
