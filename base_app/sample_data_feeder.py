import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "base_app.settings")

django.setup()

from models import Clinic

sample_data = [
    {
        "clinic_name": "Sunset Medical Center",
        "clinic_logo": "",
        "clinic_contact_number": "+1122334455",
        "clinic_address": "789 Maple Avenue",
        "clinic_city": "Cityville",
        "clinic_zipcode": 54321,
        "clinic_country": "United States",
        "clinic_email": "sunset@example.com",
    },
    {
        "clinic_name": "Bluebird Family Clinic",
        "clinic_logo": "",
        "clinic_contact_number": "+9988776655",
        "clinic_address": "456 Oak Street",
        "clinic_city": "Townsville",
        "clinic_zipcode": 12345,
        "clinic_country": "United States",
        "clinic_email": "bluebird@example.com",
    },
    {
        "clinic_name": "Greenleaf Wellness Center",
        "clinic_logo": "",
        "clinic_contact_number": "+3344556677",
        "clinic_address": "123 Elm Avenue",
        "clinic_city": "Villageville",
        "clinic_zipcode": 98765,
        "clinic_country": "United States",
        "clinic_email": "greenleaf@example.com",
    },
    {
        "clinic_name": "Golden Gate Medical Group",
        "clinic_logo": "",
        "clinic_contact_number": "+5566778899",
        "clinic_address": "789 Pine Lane",
        "clinic_city": "Citytown",
        "clinic_zipcode": 23456,
        "clinic_country": "United States",
        "clinic_email": "goldengate@example.com",
    },
    {
        "clinic_name": "Silverlake Health Center",
        "clinic_logo": "",
        "clinic_contact_number": "+8899776655",
        "clinic_address": "567 Cedar Road",
        "clinic_city": "Townville",
        "clinic_zipcode": 87654,
        "clinic_country": "United States",
        "clinic_email": "silverlake@example.com",
    },
    {
        "clinic_name": "Emerald Medical Associates",
        "clinic_logo": "",
        "clinic_contact_number": "+2233445566",
        "clinic_address": "901 Walnut Street",
        "clinic_city": "Suburbia",
        "clinic_zipcode": 34567,
        "clinic_country": "United States",
        "clinic_email": "emerald@example.com",
    },
    {
        "clinic_name": "Amber Family Clinic",
        "clinic_logo": "",
        "clinic_contact_number": "+9988776655",
        "clinic_address": "789 Oak Street",
        "clinic_city": "Hamletown",
        "clinic_zipcode": 98765,
        "clinic_country": "United States",
        "clinic_email": "amber@example.com",
    },
    {
        "clinic_name": "Sapphire Medical Center",
        "clinic_logo": "",
        "clinic_contact_number": "+5566778899",
        "clinic_address": "345 Elm Drive",
        "clinic_city": "Countryside",
        "clinic_zipcode": 65432,
        "clinic_country": "United States",
        "clinic_email": "sapphire@example.com",
    },
    {
        "clinic_name": "Apollo Hospitals",
        "clinic_logo": "",
        "clinic_contact_number": "+911234567890",
        "clinic_address": "123 MG Road",
        "clinic_city": "Mumbai",
        "clinic_zipcode": 400001,
        "clinic_country": "India",
        "clinic_email": "apollo@example.com",
    },
    {
        "clinic_name": "Fortis Hospital",
        "clinic_logo": "",
        "clinic_contact_number": "+912345678901",
        "clinic_address": "456 Park Street",
        "clinic_city": "Delhi",
        "clinic_zipcode": 110001,
        "clinic_country": "India",
        "clinic_email": "fortis@example.com",
    },
    {
        "clinic_name": "Beijing Traditional Chinese Medicine Hospital",
        "clinic_logo": "",
        "clinic_contact_number": "+8612345678901",
        "clinic_address": "789 Yinhe Street",
        "clinic_city": "Beijing",
        "clinic_zipcode": 100000,
        "clinic_country": "China",
        "clinic_email": "bth@example.com",
    },
    {
        "clinic_name": "Hospital Universitario La Paz",
        "clinic_logo": "",
        "clinic_contact_number": "+34123456789",
        "clinic_address": "123 Calle Mayor",
        "clinic_city": "Madrid",
        "clinic_zipcode": 28046,
        "clinic_country": "Spain",
        "clinic_email": "hulp@example.com",
    },
    {
        "clinic_name": "St Thomas' Hospital",
        "clinic_logo": "",
        "clinic_contact_number": "+441234567890",
        "clinic_address": "456 Lambeth Palace Road",
        "clinic_city": "London",
        "clinic_zipcode": 46152,
        "clinic_country": "United Kingdom",
        "clinic_email": "sthospital@example.com",
    },
    {
        "clinic_name": "Barts Health NHS Trust",
        "clinic_logo": "",
        "clinic_contact_number": "+441234567891",
        "clinic_address": "789 St John Street",
        "clinic_city": "London",
        "clinic_zipcode": 81555,
        "clinic_country": "United Kingdom",
        "clinic_email": "bartshealth@example.com",
    },
]

for data in sample_data:
    instance = Clinic(**data)
    instance.save()

