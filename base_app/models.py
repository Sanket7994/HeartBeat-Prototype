# Imports
import uuid
import stripe
import json
from collections import Counter
from decimal import Decimal
from django.db.models import Sum
from django.utils import timezone
from django.conf import settings
from datetime import time, date, timedelta
from datetime import datetime
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models, transaction
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
from phonenumber_field.modelfields import PhoneNumberField
from django_resized import ResizedImageField
from django.utils.deconstruct import deconstructible


# Custom User Model
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_admin", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_admin") is not True:
            raise ValueError("Superuser must be Admin")
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must be staff")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser = True")

        return self.create_user(email, password, **extra_fields)


# For Backend Admins
class CustomUser(AbstractBaseUser, PermissionsMixin):
    class Roles(models.TextChoices):
        OPERATOR = ("OPERATOR", "Operator")
        CLINIC_MANAGEMENT = ("CLINIC_MANAGEMENT", "Clinic Management")

    select_role = models.CharField(
        max_length=100, choices=Roles.choices, default=None, null=True
    )
    id = models.CharField(unique=True, primary_key=True, max_length=50, editable=False)
    email = models.EmailField(unique=True, blank=False, null=False)
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    avatar = ResizedImageField(
        size=[150, 150],
        default="avatar.jpg",
        upload_to="profile_avatars",
        blank=True,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_operator = models.BooleanField(default=False)
    is_clinic_management = models.BooleanField(default=False)
    username = None

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        if not self.id:
            while True:
                # Give Unique ID as per designation of the user
                if self.is_admin:
                    new_id = str("BA-" + str(uuid.uuid4().hex[:10].upper()))
                elif self.is_operator:
                    new_id = str("OP-" + str(uuid.uuid4().hex[:10].upper()))
                elif self.is_clinic_management:
                    new_id = str("CM-" + str(uuid.uuid4().hex[:10].upper()))
                # If user doesn`t exit in database give him a new id
                if not CustomUser.objects.filter(id=new_id).exists():
                    self.id = new_id
                    break
        super().save(*args, **kwargs)


# Clinic Model
class Clinic(models.Model):
    class StatusCode(models.TextChoices):
        APPROVED = ("APPROVED", "Approved")
        PENDING = ("PENDING", "Pending")
        CANCELLED = ("CANCELLED", "Cancelled")

    class Country(models.TextChoices):
        UK = ("UK", "UNITED KINGDOM")
        IN = ("IN", "INDIA")
        US = ("US", "UNITED STATES OF AMERICA")
        ES = ("ES", "SPAIN")
        CN = ("CN", "CHINA")

    clinic_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    clinic_name = models.CharField(max_length=100, blank=False, null=False)
    clinic_logo = ResizedImageField(
        size=[150, 150],
        default="avatar.jpg",
        upload_to="profile_avatars",
        blank=True,
        null=True,
    )
    clinic_contact_number = PhoneNumberField(
        blank=True,
        null=True,
        default=None,
        validators=[RegexValidator(r"^(\+\d{1,3})?,?\s?\d{8,15}")],
    )
    clinic_address = models.CharField(max_length=250, blank=True, null=True)
    clinic_city = models.CharField(max_length=100, blank=True, null=True)
    clinic_zipcode = models.IntegerField(blank=True, null=True)
    clinic_country = models.CharField(
        max_length=100, choices=Country.choices, default=None, null=True
    )
    clinic_email = models.EmailField(blank=True, null=True)
    clinic_status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    def __str__(self):
        return f"{self.clinic_id} : {self.clinic_name}"

    def get_full_address(self):
        return f"{self.clinic_address}, \n{self.clinic_city}, {self.clinic_country}, \nZipCode: {self.clinic_zipcode}"

    def save(self, *args, **kwargs):
        if not self.clinic_id:
            while True:
                # Generate a new unique ID
                new_clinic_id = str(uuid.uuid4().hex[:10].upper())
                # Check if the generated ID already exists in the database
                if not Clinic.objects.filter(clinic_id=new_clinic_id).exists():
                    self.clinic_id = new_clinic_id
                    break
        super().save(*args, **kwargs)


# clinic Members
class ClinicMember(models.Model):
    class StatusCode(models.TextChoices):
        APPROVED = ("APPROVED", "Approved")
        PENDING = ("PENDING", "Pending")
        CANCELLED = ("CANCELLED", "Cancelled")

    class StaffDesignation(models.TextChoices):
        IVF_COORDINATOR = "IVF_COORDINATOR", "IVF Coordinator"
        DONOR_COORDINATOR = "DONOR_COORDINATOR", "Donor Coordinator"
        RECEPTIONIST = "RECEPTIONIST", "Receptionist"
        ADMIN = "ADMIN", "Admin"
        DOCTOR_PHYSICIST = "DOCTOR_PHYSICIST", "Doctor/Physicist"
        EMBRYOLOGY = "EMBRYOLOGY", "Embryology"
        NURSE = "NURSE", "Nurse"
        LABORATORY = "LABORATORY", "Laboratory"
        PSYCHOLOGIST_COUNSELLOR = "PSYCHOLOGIST_COUNSELLOR", "Psychologist/Counsellor"

    class Shift_type(models.TextChoices):
        GENERAL_SHIFT = (
            "General Shift 9AM - 6PM",
            f"{time(9, 0).strftime('%I:%M %p')} - {time(18, 0).strftime('%I:%M %p')}",
        )
        FLEX_SHIFT_1 = (
            "Flex Shift 10AM - 2PM",
            f"{time(10, 0).strftime('%I:%M %p')} - {time(14, 0).strftime('%I:%M %p')}",
        )
        FLEX_SHIFT_2 = (
            "Flex Shift 3PM - 7PM",
            f"{time(15, 0).strftime('%I:%M %p')} - {time(19, 0).strftime('%I:%M %p')}",
        )
        FRONT_LINE_SHIFT_1 = (
            "Front Line Shift 7AM - 7PM",
            f"{time(7, 0).strftime('%I:%M %p')} - {time(19, 0).strftime('%I:%M %p')}",
        )
        FRONT_LINE_SHIFT_2 = (
            "Front Line Shift 7PM - 7AM",
            f"{time(19, 0).strftime('%I:%M %p')} - {time(7, 0).strftime('%I:%M %p')}",
        )

    staff_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    clinic_name = models.ForeignKey(Clinic, on_delete=models.SET_NULL, null=True)
    staff_first_name = models.CharField(max_length=100, blank=False, null=False)
    staff_last_name = models.CharField(max_length=100, blank=False, null=False)
    staff_avatar = ResizedImageField(
        size=[150, 150],
        default="avatar.jpg",
        upload_to="profile_avatars",
        blank=True,
        null=True,
    )
    staff_designation = models.CharField(
        max_length=100, choices=StaffDesignation.choices, default=None, null=True
    )
    shift_type = models.CharField(
        max_length=100, choices=Shift_type.choices, default=Shift_type.GENERAL_SHIFT
    )
    staff_email = models.EmailField(blank=True, null=True)
    staff_contact_number = PhoneNumberField(
        default=None,
        null=True,
        blank=True,
        validators=[RegexValidator(r"^(\+\d{1,3})?,?\s?\d{8,15}")],
    )
    staff_status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    def __str__(self):
        return f"{self.staff_id} : {self.staff_first_name} {self.staff_last_name}"

    def save(self, *args, **kwargs):
        if not self.staff_id:
            while True:
                new_staff_id = str(uuid.uuid4().hex[:10].upper())
                if not ClinicMember.objects.filter(staff_id=new_staff_id).exists():
                    self.staff_id = new_staff_id
                    break
        super().save(*args, **kwargs)


# Medical Procedures
class MedicalProceduresTypes(models.Model):
    class MyChoices(models.TextChoices):
        MEDICAL_EXAMINATION = ("MEDICAL_EXAMINATION", "Medical Examination")
        ROUTINE_CHECK_UP = ("ROUTINE_CHECK_UP", "Routine Check-up")
        RESULT_ANALYSIS = ("RESULT_ANALYSIS", "Result Analysis")
        BLOOD_TESTS = ("BLOOD_TESTS", "Blood Tests")
        X_RAY = ("X_RAY", "X-ray")
        ULTRASOUND = ("ULTRASOUND", "Ultrasound")
        VACCINATIONS = ("VACCINATIONS", "Vaccinations")
        BIOPSY = ("BIOPSY", "Biopsy")
        SURGERY = ("SURGERY", "Surgery")
        PHYSICAL_THERAPY = ("PHYSICAL_THERAPY", "Physical Therapy")
        HEARING_TEST = ("HEARING_TEST", "Hearing Test")
        VISION_TEST = ("VISION_TEST", "Vision Test")
        CARDIAC_STRESS_TEST = ("CARDIAC_STRESS_TEST", "Cardiac Stress Test")
        ORGAN_DONATION = ("ORGAN_DONATION", "Organ Donation")
        CONSULTATION = ("CONSULTATION", "Consultation")
        OTHER = ("OTHER", "Other")

    procedure_choice = models.CharField(
        choices=MyChoices.choices, default=MyChoices.OTHER, max_length=154, unique=True
    )

    def __str__(self):
        return self.procedure_choice


# Create appointments
class PatientAppointment(models.Model):
    class StatusCode(models.TextChoices):
        APPROVED = "APPROVED", "Approved"
        PENDING = "PENDING", "Pending"
        CANCELLED = "CANCELLED", "Cancelled"

    class Gender(models.TextChoices):
        MALE = "MALE", "Male"
        FEMALE = "FEMALE", "Female"
        UNDISCLOSED = "UNDISCLOSED", "Undisclosed"

    def validate_date(value):
        if value < timezone.now().date():
            raise ValidationError(_("Invalid date."))

    def validate_weekday(value):
        if value.weekday() >= 5:
            raise ValidationError(_("Appointments are not available on weekends."))

    appointment_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    clinic_name = models.ForeignKey(
        Clinic,
        on_delete=models.SET_NULL,
        null=True,
        related_name="main_clinic_name",
    )
    relatedDepartment = models.CharField(max_length=100, blank=True, null=True)
    relatedRecipient = models.ForeignKey(
        ClinicMember,
        on_delete=models.SET_NULL,
        null=True,
        related_name="recipient_name",
    )
    patient_social_security_ID = models.CharField(
        max_length=10, unique=True, blank=True, null=True
    )
    patient_first_name = models.CharField(max_length=150)
    patient_last_name = models.CharField(max_length=150, null=False, blank=False)
    patient_gender = models.CharField(
        max_length=100, choices=Gender.choices, default=None, null=True
    )
    date_of_birth = models.DateField(blank=True, null=True)
    patient_age = models.IntegerField(blank=True, null=True)
    patient_email = models.EmailField(blank=True, null=True)
    patient_contact_number = PhoneNumberField(
        blank=True,
        null=True,
        validators=[RegexValidator(r"^(\+\d{1,3})?,?\s?\d{8,15}")],
        default=None,
    )
    recurring_patient = models.BooleanField(default=False)
    procedures = models.ManyToManyField(MedicalProceduresTypes)
    appointment_description = models.TextField(blank=True, null=True)
    appointment_date = models.DateField(
        validators=[validate_date, validate_weekday],
        default=timezone.now,
    )
    appointment_slot = models.CharField(blank=False, max_length=50)
    appointment_status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    def save(self, *args, **kwargs):
        if self.date_of_birth:
            today = date.today()
            patient_age = today.year - self.date_of_birth.year

            # Check if the birthday has already occurred this year
            if today.month < self.date_of_birth.month or (
                today.month == self.date_of_birth.month
                and today.day < self.date_of_birth.day
            ):
                patient_age -= 1
            self.patient_age = patient_age

        # Saving Appointment reference number
        if not self.appointment_id:
            while True:
                new_appointment_id = str(uuid.uuid4().hex[:10].upper())
                if not PatientAppointment.objects.filter(
                    appointment_id=new_appointment_id
                ).exists():
                    self.appointment_id = new_appointment_id
                    break

        super().save(*args, **kwargs)

        if self.procedures.exists():
            count_dict = Counter(
                item.procedure_choice for item in self.procedures.all()
            )
            return count_dict

        # Check if patient exists in ClientDataCollectionPool
        # by checking their unique social security ID
        try:
            with transaction.atomic():
                client = ClientDataCollectionPool.objects.get(
                    client_social_security_ID=self.patient_social_security_ID
                )

        except ClientDataCollectionPool.DoesNotExist:
            # Patient doesn't exist, create a new client
            client = ClientDataCollectionPool()
            client.client_social_security_ID = self.patient_social_security_ID
            client.client_first_name = self.patient_first_name
            client.client_last_name = self.patient_last_name
            client.client_dob = self.date_of_birth
            client.client_gender = self.patient_gender
            client.client_contact_number = self.patient_contact_number
            client.client_email = self.patient_email
            client.appointment_count = 1
            client.medical_procedure_history = count_dict
            client.save()
        else:
            # Patient exists, update client contact fields
            client.client_contact_number = self.patient_contact_number
            client.client_email = self.patient_email
            # Increment appointment count If patient is recurring
            client.appointment_count = int(client.appointment_count) + 1
            # Update count of Medical procedures taken If patient is recurring
            updated_medical_procedure_history = dict(
                Counter(
                    **client.medical_procedure_history,
                    **self.procedures.values_list("procedure_choice", flat=True),
                )
            )
            client.medical_procedure_history = updated_medical_procedure_history
            client.save()

    def __str__(self):
        return self.appointment_id


# Address Validation and json defaults
def validate_address(self, address):
    required_fields = ["country", "state", "city", "line1", "line2", "postal_code"]
    for field in required_fields:
        if field not in address:
            address[field] = ""


def default_address():
    return {
        "country": "",
        "state": "",
        "city": "",
        "line1": "",
        "line2": "",
        "postal_code": "",
    }


# Auto update or create patient database
class ClientDataCollectionPool(models.Model):
    def default_json_fields():
        return dict

    client_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    client_social_security_ID = models.CharField(
        max_length=10, unique=True, blank=True, null=True
    )
    stripe_customer_id = models.CharField(max_length=250, blank=True, null=True)
    client_first_name = models.CharField(max_length=100, blank=True, null=True)
    client_last_name = models.CharField(max_length=100, blank=True, null=True)
    client_dob = models.DateField(blank=True, null=True)
    client_gender = models.CharField(max_length=10, default="UNDISCLOSED")
    client_contact_number = models.CharField(max_length=16, blank=True, null=True)
    client_email = models.EmailField(max_length=250, blank=True, null=True)
    client_shipping_address = models.JSONField(
        default=default_address, blank=True, null=True
    )
    client_billing_address = models.JSONField(
        default=default_address, blank=True, null=True
    )
    appointment_count = models.IntegerField(default=0, blank=True, null=True)
    medical_procedure_history = models.JSONField(
        default=default_json_fields(), blank=True, null=True
    )
    prescription_count = models.IntegerField(default=0, blank=True, null=True)
    medication_history = models.JSONField(
        default=default_json_fields(), blank=True, null=True
    )
    transactions_made = models.JSONField(
        default=default_json_fields(), blank=True, null=True
    )
    total_billings = models.DecimalField(default=0.0, decimal_places=2, max_digits=10)
    profile_last_updated = models.DateTimeField(auto_now=True)
    profile_created_at = models.DateTimeField(auto_now_add=True, editable=False)

    def save(self, *args, **kwargs):
        if not self.client_id:
            while True:
                new_client_id = str(f"CL-" + uuid.uuid4().hex[:5].upper())
                if not ClientDataCollectionPool.objects.filter(
                    client_id=new_client_id
                ).exists():
                    self.client_id = new_client_id
                    break

        if self.client_shipping_address:
            address = self.client_shipping_address
            validate_address(self, address)

        if self.client_billing_address:
            address = self.client_billing_address
            validate_address(self, address)

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.client_id} : {self.client_first_name} {self.client_last_name}"


# Pharmacy Drug Inventory
class PharmacyInventory(models.Model):
    class DosageType(models.TextChoices):
        ORAL = "ORAL", "Oral"
        OPHTHALMIC = "OPHTHALMIC", "Ophthalmic"
        INHALATION = "INHALATION", "Inhalation"
        INJECTION = "INJECTION", "Injection"
        TOPICAL = "TOPICAL", "Topical"
        OTHER = "OTHER", "Other"

    class GeneralDrugClass(models.TextChoices):
        ANALGESICS = (
            "ANALGESICS: Used for headaches, muscle pain, toothaches, menstrual pain",
            "ANALGESICS",
        )
        ANTIPYRETICS = ("ANTIPYRETICS: Used to reduce fever", "ANTIPYRETICS")
        ANTACIDS = (
            "ANTACIDS: Used for heartburn, indigestion, acid reflux",
            "ANTACIDS",
        )
        ANTIHISTAMINES = (
            "ANTIHISTAMINES: Used for allergies, itchy skin or eyes, sneezing, runny nose",
            "ANTIHISTAMINES",
        )
        COUGH_AND_COLD = (
            "COUGH AND COLD: Used for cough relief, nasal congestion, sore throat",
            "COUGH_AND_COLD",
        )
        TOPICAL_ANALGESICS = (
            "TOPICAL ANALGESICS: Used for muscle aches and strains, joint pain, minor injuries",
            "TOPICAL_ANALGESICS",
        )
        ANTIDIARRHEALS = ("ANTIDIARRHEALS: Used for diarrhea relief", "ANTIDIARRHEALS")
        DERMATOLOGICAL = (
            "DERMATOLOGICAL: Used for acne treatment, eczema or dermatitis management, fungal infections",
            "DERMATOLOGICAL",
        )
        ORAL_CONTRACEPTIVES = (
            "ORAL CONTRACEPTIVES: Used for pregnancy prevention",
            "ORAL_CONTRACEPTIVES",
        )
        OPHTHALMIC = (
            "OPHTHALMIC: Used for eye infections, dry eyes, allergic conjunctivitis",
            "OPHTHALMIC",
        )
        OTHER = ("Other", "OTHER")

    class UnitType(models.TextChoices):
        SINGLE_UNIT = "SINGLE_UNIT", "Single Unit"
        PACK_OF_10 = "PACK_OF_10", "Pack of 10"
        PACK_OF_50 = "PACK_OF_50", "Pack of 50"

    drug_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )

    stripe_product_id = models.CharField(
        max_length=255, blank=True, null=True, editable=False
    )
    drug_name = models.CharField(max_length=250, unique=True)
    drug_image = ResizedImageField(
        size=[150, 150],
        default="default_image.png",
        upload_to="Drug_Stock_Images",
        blank=True,
        null=True,
    )
    generic_name = models.CharField(max_length=250)
    brand_name = models.CharField(max_length=250)
    drug_class = models.CharField(
        choices=GeneralDrugClass.choices,
        default=GeneralDrugClass.OTHER,
        max_length=250,
    )
    dosage_form = models.CharField(
        choices=DosageType.choices,
        default=DosageType.OTHER,
        max_length=250,
    )
    unit_type = models.CharField(
        choices=UnitType.choices,
        default=UnitType.SINGLE_UNIT,
        max_length=250,
    )
    price = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    stripe_price_id = models.CharField(
        max_length=255, blank=True, null=True, editable=False
    )
    add_new_stock = models.PositiveIntegerField(default=0, help_text="add_quantity")
    stock_available = models.PositiveIntegerField(
        default=0, editable=False, help_text="available_stock"
    )
    stock_history = models.TextField(
        default="[]", editable=False, help_text="stock history"
    )
    manufacture_date = models.DateField(default=timezone.now)
    lifetime_in_months = models.PositiveIntegerField(
        default=0, help_text="number_of_months"
    )
    expiry_date = models.DateField(default=None, blank=True, null=True, editable=False)
    added_at = models.DateTimeField(auto_now_add=True, editable=False)

    def save(self, *args, **kwargs):
        # Update Stock If new quantity is added
        if self.add_new_stock:
            new_stock = int(self.stock_available) + int(self.add_new_stock)
            self.stock_available = new_stock
            # Store the new entry in stock_history
            stock_history = json.loads(self.stock_history)
            new_entry = {
                "quantity": self.add_new_stock,
                "date": f"{datetime.now():%d-%m-%Y %H:%M:%S}",
            }
            stock_history.append(new_entry)
            self.stock_history = json.dumps(stock_history)
            # Reset add_new_stock to default value
            self.add_new_stock = 0

        # Add expiry date and
        if self.manufacture_date and self.lifetime_in_months:
            expiry_date = self.manufacture_date + timedelta(
                days=30 * self.lifetime_in_months
            )
            self.expiry_date = expiry_date

        # Generate ID
        if not self.drug_id:
            while True:
                new_drug_id = str("MED-" + str(uuid.uuid4().hex[:10].upper()))
                if not PharmacyInventory.objects.filter(drug_id=new_drug_id).exists():
                    self.drug_id = new_drug_id
                    break

        # Create Stripe product and price if IDs are not set
        if not self.stripe_product_id:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            product = stripe.Product.create(name=self.drug_name)
            self.stripe_product_id = product.id

        if not self.stripe_price_id:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            price = stripe.Price.create(
                product=self.stripe_product_id,
                unit_amount=int(self.price * 100),  # Stripe expects the amount in cents
                currency="usd",  # Change to your desired currency
            )
            self.stripe_price_id = price.id

        super().save(*args, **kwargs)

    def __str__(self):
        return self.drug_name


# Prescription Model
class Prescription(models.Model):
    class StatusCode(models.TextChoices):
        APPROVED = "APPROVED", "Approved"
        PENDING = "PENDING", "Pending"
        CANCELLED = "CANCELLED", "Cancelled"

    class DosingFrequency(models.TextChoices):
        ONCE_A_DAY = "ONCE_A_DAY", "Once a day"
        TWICE_A_DAY = "TWICE_A_DAY", "Twice a day"
        THRICE_A_DAY = "THRICE_A_DAY", "Thrice a day"
        FLEXIBLE = "FLEXIBLE", "Flexible timings"

    def default_json_fields():
        return dict

    prescription_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    clinic_name = models.ForeignKey(
        Clinic,
        on_delete=models.SET_NULL,
        null=True,
        related_name="prescriptions",
    )
    consultant = models.ForeignKey(
        ClinicMember,
        on_delete=models.SET_NULL,
        null=True,
        related_name="prescriptions",
    )
    appointment_id = models.ForeignKey(
        PatientAppointment,
        on_delete=models.SET_NULL,
        null=True,
        related_name="prescriptions",
    )
    medications_json = models.JSONField(
        default=default_json_fields(), blank=True, null=True
    )
    shipping_address = models.JSONField(default=default_address, blank=True, null=True)
    stripe_appointment_service_id = models.CharField(
        max_length=250, blank=True, null=True
    )
    stripe_appointment_price_id = models.CharField(
        max_length=250, blank=True, null=True
    )
    stripe_client_id = models.CharField(max_length=100, blank=True, null=True)
    appointment_fee = models.DecimalField(
        default=0, max_digits=10, decimal_places=2, editable=False
    )
    med_bill_amount = models.DecimalField(
        default=0, max_digits=10, decimal_places=2, editable=False
    )
    coupon_discount = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    grand_total = models.DecimalField(
        default=0, max_digits=10, decimal_places=2, editable=False
    )
    description = models.TextField(max_length=300, blank=True, null=True)
    approval_status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    payment_status = models.CharField(max_length=100, default="UNPAID")
    created_at = models.DateTimeField(auto_now_add=True, editable=False)


    def save(self, *args, **kwargs):
        
        if self.medications_json:
            medications = json.loads(self.medications_json)

            total_med_amount = Decimal(0)
            for medicine in medications:
                total_payable_amount = Decimal(medicine["total_payable_amount"])
                total_med_amount += total_payable_amount

            # Adding appointment charge
            self.appointment_fee = Decimal("100.00")
            self.med_bill_amount = total_med_amount
            self.grand_total = (self.med_bill_amount + self.appointment_fee) - self.coupon_discount

            try:
                with transaction.atomic():
                    client = ClientDataCollectionPool.objects.get(
                        client_social_security_ID=self.appointment_id.patient_social_security_ID
                    )

                    if not isinstance(client.medication_history, dict):
                        medication_history_dict = {}
                        for medication in client.medication_history:
                            medication_id = medication["medicine_id"]
                            quantity = medication["quantity"]
                            medication_history_dict[medication_id] = quantity
                        client.medication_history = medication_history_dict

                    # Extract the medicine IDs as keys and quantities as values for all medications
                    medicine_load = {}
                    if self.medications_json:
                        medications = json.loads(self.medications_json)
                        for medication in medications:
                            medicine_id = medication["medicine_id"]
                            quantity = medication["quantity"]
                            medicine_load[medicine_id] = quantity
                    else:
                        medicine_load = {}

                    client.prescription_count += 1
                    updated_medication_history = {
                        **client.medication_history,
                        **medicine_load,
                    }
                    client.medication_history = updated_medication_history
                    client.client_shipping_address = self.shipping_address
                    client.stripe_customer_id = self.stripe_client_id
                    client.save()

            except ClientDataCollectionPool.DoesNotExist:
                return "Client Data doesn't exist. Client must be seen by a physician/doctor before receiving a prescription"
        
        # Checking if UID exists  
        if not self.prescription_id:
            while True:
                new_prescription_id = str("P-" + str(uuid.uuid4().hex[:10].upper()))
                if not Prescription.objects.filter(
                    prescription_id=new_prescription_id
                ).exists():
                    self.prescription_id = new_prescription_id
                    break

        if not self.stripe_appointment_service_id:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            self.stripe_appointment_service_id = settings.APPOINTMENT_SERVICE_ID

        if not self.stripe_appointment_price_id:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            self.stripe_appointment_price_id = settings.APPOINTMENT_PRICE_ID

        super().save(*args, **kwargs)
        
    @classmethod
    def get_total_due_amount(cls):
        total_due = Prescription.objects.aggregate(total=Sum('grand_total'))
        return round(total_due['total'], 2) if total_due['total'] else 0.00

    def __str__(self):
        return str(self.prescription_id)



# Customer Post payment service feedback model
class ClientServiceFeedback(models.Model):
    customer_id = models.CharField(max_length=250, blank=True, null=True)
    overall_rating = models.PositiveIntegerField(default=3, null=True, blank=True)
    comment = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ID: {self.id} - {self.created_at} - {self.comment[:15]}..."
