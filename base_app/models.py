# Imports
import uuid
import stripe
import json
import random
from collections import Counter
from decimal import Decimal
from django.db.models import Sum
from django.utils import timezone
from django.conf import settings
from datetime import datetime, date, timedelta
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from .choice_fields import (
    ProcedureChoices,
    StatusCode,
    Country,
    DosingFrequency,
    EmployeeStatusCode,
    StaffDesignation,
    Shift_type,
    Gender,
    TaskStatusCode,
    SetPriority,
    TaskType,
    LabelChoices,
    DosageType,
    GeneralDrugClass,
    UnitType,
    BudgetPeriodType,
)
from django.db import models, transaction
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ObjectDoesNotExist
from phonenumber_field.modelfields import PhoneNumberField
from django_resized import ResizedImageField
from django.core.validators import URLValidator
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
        CLINIC_MANAGEMENT = ("CLINIC_MANAGEMENT", "Clinic Management")
        SUPER_ADMIN = ("SUPER_ADMIN", "SuperAdmin")

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
    is_clinic_management = models.BooleanField(default=False)
    is_super_admin = models.BooleanField(default=False)
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
                elif self.is_super_admin:
                    new_id = str("SA-" + str(uuid.uuid4().hex[:10].upper()))
                elif self.is_clinic_management:
                    new_id = str("CM-" + str(uuid.uuid4().hex[:10].upper()))
                # If user doesn`t exit in database give him a new id
                if not CustomUser.objects.filter(id=new_id).exists():
                    self.id = new_id
                    break
        super().save(*args, **kwargs)


# Clinic Model
class Clinic(models.Model):
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
    def validate_date(value):
        if value > timezone.now().date():
            raise ValidationError(_("Invalid date."))

    staff_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    clinic_name = models.ForeignKey(Clinic, on_delete=models.SET_NULL, null=True)
    staff_first_name = models.CharField(max_length=100, blank=False, null=False)
    staff_last_name = models.CharField(max_length=100, blank=False, null=False)
    staff_gender = models.CharField(
        max_length=100, choices=Gender.choices, default=None, null=True, blank=True
    )
    staff_date_of_birth = models.DateField(
        validators=[validate_date],
        default=None,
        null=True,
        blank=True,
    )
    staff_age = models.IntegerField(blank=True, null=True)
    staff_avatar = ResizedImageField(
        size=[150, 150],
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
    staff_fixed_salary = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    staff_status = models.CharField(
        max_length=100,
        choices=EmployeeStatusCode.choices,
        default=EmployeeStatusCode.INACTIVATE,
    )
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    def __str__(self):
        return f"{self.staff_id} : {self.staff_first_name} {self.staff_last_name}"

    def save(self, *args, **kwargs):
        # Saving unique id
        if not self.staff_id:
            while True:
                new_staff_id = str(uuid.uuid4().hex[:10].upper())
                if not ClinicMember.objects.filter(staff_id=new_staff_id).exists():
                    self.staff_id = new_staff_id
                    break
        # AUto calculate age after saving DOB
        if self.staff_date_of_birth:
            today = date.today()
            staff_age = today.year - self.staff_date_of_birth.year

            # Check if the birthday has already occurred this year
            if today.month < self.staff_date_of_birth.month or (
                today.month == self.staff_date_of_birth.month
                and today.day < self.staff_date_of_birth.day
            ):
                staff_age -= 1
            self.staff_age = staff_age

        # Setting up default profile pictures
        if self.staff_gender == Gender.MALE:
            self.staff_avatar = "default-male-profile-pic.png"
        elif self.staff_gender == Gender.FEMALE:
            self.staff_avatar = "default-female-profile-pic.png"
        elif self.staff_gender == Gender.UNDISCLOSED:
            self.staff_avatar = "avatar.jpg"
        super().save(*args, **kwargs)


# User Todo List
class TaskAssignmentManager(models.Model):
    def default_json():
        return {}

    task_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    task_title = models.CharField(max_length=100, blank=True, null=True, default=None)
    assignor = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    department = models.CharField(
        max_length=100,
        choices=StaffDesignation.choices,
        default=None,
        null=True,
    )
    assignee = models.CharField(max_length=100, blank=True, null=True, default=None)
    add_collaborators = models.JSONField(blank=True, null=True, default=default_json)
    sub_tasks = models.JSONField(default=default_json, blank=True, null=True)
    task_thread = models.JSONField(default=default_json, blank=True, null=True)
    priority = models.CharField(
        max_length=100, choices=SetPriority.choices, default=SetPriority.LOW
    )
    task_status = models.CharField(
        max_length=100, choices=TaskStatusCode.choices, default=TaskStatusCode.PENDING
    )
    set_deadline = models.DateField(default=None, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.task_id:
            while True:
                new_task_id = str(f"TSK-" + uuid.uuid4().hex[:10].upper())
                if not TaskAssignmentManager.objects.filter(
                    task_id=new_task_id
                ).exists():
                    self.task_id = new_task_id
                    break
        super().save(*args, **kwargs)

    def __str__(self):
        return self.task_id


class PersonalJournal(models.Model):
    def default_json():
        return []

    note_id = models.IntegerField(
        primary_key=True, editable=False, unique=True, auto_created=True
    )
    creator = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    note_title = models.CharField(max_length=100, default=None, null=True, blank=True)
    note_content = models.TextField(blank=True, null=True)
    check_list = models.JSONField(blank=True, null=True, default=default_json)
    reminder = models.DateTimeField(default=None, null=True, blank=True)
    label = models.CharField(max_length=100, choices=LabelChoices.choices, default=None)
    archive_status = models.BooleanField(default=False)
    created_on = models.DateTimeField(auto_now_add=True)
    edit_timeline = models.JSONField(blank=True, null=True, default=default_json)

    def __str__(self):
        return f"{self.creator} - {self.note_id}"


# Medical Procedures
class MedicalProceduresTypes(models.Model):
    procedure_choice = models.CharField(
        choices=ProcedureChoices.choices,
        default=ProcedureChoices.MEDICAL_EXAMINATION,
        max_length=154,
        unique=True,
    )
    stripe_service_id = models.CharField(max_length=256, blank=True, null=True)
    stripe_service_price_id = models.CharField(max_length=256, blank=True, null=True)
    fixed_cost = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    
    def save(self, *args, **kwargs):
        stripe.api_key = settings.STRIPE_SECRET_KEY
        # Create Stripe product and price if IDs are not set
        if not self.stripe_service_id:
            service = stripe.Product.create(name=self.procedure_choice)
            self.stripe_service_id = service.id

        if not self.stripe_service_price_id:
            price = stripe.Price.create(product=self.stripe_service_id, 
                                        unit_amount=int(self.fixed_cost * 100), 
                                        currency="usd")
            self.stripe_service_price_id = price.id
        super().save(*args, **kwargs)

    def __str__(self):
        return self.procedure_choice


# Create appointments
class PatientAppointment(models.Model):
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
    patient_contact_number = models.CharField(max_length=18, blank=True, null=True)
    procedures = models.ManyToManyField(
        MedicalProceduresTypes, related_name="procedure_choice_per_patient"
    )
    total_procedure_cost = models.DecimalField(
        default=0, max_digits=10, decimal_places=2
    )
    appointment_description = models.TextField(blank=True, null=True)
    appointment_date = models.DateField(
        # validators=[validate_date, validate_weekday],
        default=timezone.now,
    )
    appointment_slot = models.CharField(blank=False, max_length=50, null=True)
    appointment_status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=None, blank=True, null=True
    )
    recurring_patient = models.BooleanField(default=False)
    patient_consent_agreement = models.BooleanField(default=False)
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField()

    def get_procedure_counts(self):
        return Counter(item.procedure_choice for item in self.procedures.all())

    def calculate_total_procedure_cost(self):
        total_cost = Decimal("0.00")
        for procedure in self.procedures.all():
            procedure_data = (
                MedicalProceduresTypes.objects.filter(procedure_choice=procedure)
                .values("fixed_cost")
                .first()
            )
            if procedure_data:
                total_cost += Decimal(procedure_data["fixed_cost"])

        return total_cost.quantize(Decimal("0.00"))

    def save(self, *args, **kwargs):
        if self.date_of_birth:
            today = date.today()
            patient_age = today.year - self.date_of_birth.year

            if today.month < self.date_of_birth.month or (
                today.month == self.date_of_birth.month
                and today.day < self.date_of_birth.day
            ):
                patient_age -= 1
            self.patient_age = patient_age

        if self.relatedRecipient:
            recipient_id = self.relatedRecipient.staff_id
            recipient_data = (
                ClinicMember.objects.filter(staff_id=recipient_id).values().first()
            )
            self.relatedDepartment = recipient_data["staff_designation"]

        if not self.appointment_id:
            while True:
                new_appointment_id = str(uuid.uuid4().hex[:10].upper())
                if not PatientAppointment.objects.filter(
                    appointment_id=new_appointment_id
                ).exists():
                    self.appointment_id = new_appointment_id
                    break
                
        if self.procedures.exists():
            self.total_procedure_cost = self.calculate_total_procedure_cost()

        super().save(*args, **kwargs)

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
            client.medical_procedure_history = self.get_procedure_counts()
            client.save()
        else:
            # Patient exists, update client contact fields
            client.client_contact_number = self.patient_contact_number
            client.client_email = self.patient_email
            # Increment appointment count If patient is recurring
            client.appointment_count += 1
            # Update count of Medical procedures taken If patient is recurring
            procedure_choices_qs = self.procedures.values_list(
                "procedure_choice", flat=True
            )
            procedure_choices_list = list(procedure_choices_qs)
            updated_medical_procedure_history = Counter(
                client.medical_procedure_history
            ) + Counter(procedure_choices_list)
            client.medical_procedure_history = dict(updated_medical_procedure_history)
            client.save()

    @classmethod
    def get_total_procedure_amount(cls):
        total_amount = PatientAppointment.objects.aggregate(total=Sum("total_procedure_cost"))
        return round(total_amount["total"], 2) if total_amount["total"] else 0.00

    def __str__(self):
        return self.appointment_id


def get_current_timestamp():
    return timezone.now()


# Address Validation and json defaults
def validate_address(address):
    required_fields = ["country", "state", "city", "line1", "line2", "postal_code"]
    if len(address) != 0:
        for field in required_fields:
            if field not in address:
                address[field] = ""
        return address
    else:
        address = {
            "country": "",
            "state": "",
            "city": "",
            "line1": "",
            "line2": "",
            "postal_code": "",
        }
        return address


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
        return list

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
    client_avatar = ResizedImageField(
        size=[150, 150],
        upload_to="profile_avatars",
        blank=True,
        null=True,
    )
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
            address = validate_address(self.client_shipping_address)
            self.client_shipping_address = address

        if self.client_billing_address:
            address = validate_address(self.client_billing_address)
            self.client_billing_address = address

        if self.client_gender == "MALE":
            self.client_avatar = "default-male-profile-pic.png"
        elif self.client_gender == "FEMALE":
            self.client_avatar = "default-female-profile-pic.png"
        elif self.client_gender == "UNDISCLOSED":
            self.client_avatar = "avatar.jpg"
        super().save(*args, **kwargs)

    @classmethod
    def get_data_by_gender(cls):
        male_data = ClientDataCollectionPool.objects.filter(client_gender="MALE").values()
        female_data = ClientDataCollectionPool.objects.filter(client_gender="FEMALE").values()
        others = ClientDataCollectionPool.objects.filter(client_gender="UNDISCLOSED").values()
        data = {"Male": len(male_data), 
                "Female": len(female_data), 
                "Other": len(others)}
        return data
    
    def __str__(self):
        return f"{self.client_id} : {self.client_first_name} {self.client_last_name}"


# Pharmacy Drug Inventory
class PharmacyInventory(models.Model):
    def default_stock_history():
        return []

    drug_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    stripe_product_id = models.CharField(max_length=255, blank=True, null=True)
    drug_name = models.CharField(max_length=250, unique=True)
    drug_image_url = models.TextField(
        validators=[URLValidator()], blank=True, null=True
    )
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
        max_length=255, blank=True, null=True
    )
    add_new_stock = models.PositiveIntegerField(default=0, help_text="add_quantity")
    stock_available = models.PositiveIntegerField(
        default=0, help_text="available_stock"
    )
    stock_history = models.JSONField(
        default=default_stock_history, null=True, blank=True, help_text="stock history"
    )
    manufacture_date = models.DateField(default=timezone.now)
    lifetime_in_months = models.PositiveIntegerField(
        default=0, help_text="number_of_months"
    )
    expiry_date = models.DateField(default=None, blank=True, null=True, editable=False)
    added_at = models.DateTimeField(auto_now_add=True, editable=False)

    def save(self, *args, **kwargs):
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

    @staticmethod
    def get_drug_class_choices():
        choice_list = [choice for choice in GeneralDrugClass.choices]
        return choice_list

    def __str__(self):
        return self.drug_name


# Purchase order for drugs
class PurchaseOrder(models.Model):
    def default_file_structure():
        return {
            "drugURL": "",
            "drugId": "",
            "drugName": "",
            "priceId": "",
            "pricePerUnit": "",
            "quantity": "",
        }

    def default_thread():
        return []

    purchase_order_id = models.CharField(
        primary_key=True,
        max_length=20,
        editable=False,
        unique=True,
    )
    order = models.JSONField(default=default_file_structure, blank=True, null=True)
    total_payment_amount = models.DecimalField(
        default=0, max_digits=10, decimal_places=2
    )
    PO_report = models.FileField(
        upload_to="CSV_records", blank=True, null=True, default=None
    )
    created_by = models.CharField(max_length=250, default=None, null=True, blank=True)
    authorized_by = models.CharField(
        max_length=250, default="NA", null=True, blank=True
    )
    thread_history = models.JSONField(default=default_thread, null=True, blank=True)
    transaction_data = models.JSONField(default=default_thread, null=True, blank=True)
    payment_status = models.CharField(max_length=250, default="UNPAID")
    approval_status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    request_sent_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.purchase_order_id:
            while True:
                new_purchase_order_id = str(f"PO-" + uuid.uuid4().hex[:10].upper())
                if not PurchaseOrder.objects.filter(
                    purchase_order_id=new_purchase_order_id
                ).exists():
                    self.purchase_order_id = new_purchase_order_id
                    break
        super().save(*args, **kwargs)

    def __str__(self):
        return self.purchase_order_id


# Payment Structure for PO of medicines
class POPayment(models.Model):
    def default_thread():
        return []

    purchase_order = models.ForeignKey(
        PurchaseOrder, on_delete=models.SET_NULL, null=True
    )
    payable_amount = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    transaction_details = models.JSONField(default=default_thread, null=True)
    payment_status = models.CharField(max_length=20, default="Pending")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Payment for {self.purchase_order.purchase_order_id}"


# Prescription Model
class Prescription(models.Model):
    def default_json_fields():
        return dict

    prescription_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    appointment_id = models.ForeignKey(
        PatientAppointment,
        on_delete=models.SET_NULL,
        null=True,
        related_name="prescriptions",
    )
    clinic_name = models.CharField(max_length=250, default=None, null=True, blank=True)
    consultant = models.CharField(max_length=250, default=None, null=True, blank=True)
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
    created_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        total_procedure_cost = Decimal(0)
        total_med_amount = Decimal(0)
        
        if self.appointment_id:
            appointment_data = (
                PatientAppointment.objects.filter(appointment_id=self.appointment_id)
                .values()
                .first()
            )
            self.clinic_name = appointment_data["clinic_name_id"]
            self.consultant = appointment_data["relatedRecipient_id"]
            total_procedure_cost += appointment_data["total_procedure_cost"]

        if self.medications_json:
            medications = json.loads(self.medications_json)
            for medicine in medications:
                total_payable_amount = Decimal(medicine["total_payable_amount"])
                total_med_amount += total_payable_amount
            
            # Adding appointment charge
            self.appointment_fee = Decimal("100.00")
            self.med_bill_amount = total_med_amount
            self.grand_total = (self.med_bill_amount + 
                                self.appointment_fee + 
                                total_procedure_cost) - self.coupon_discount

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
                        
                    updated_medication_history = {
                        **client.medication_history,
                        **medicine_load,
                    }
                    client.medication_history = updated_medication_history
                    client.client_shipping_address = self.shipping_address
                    client.stripe_customer_id = self.stripe_client_id
                    client.save()

            except Exception as e:
                return str(e)

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
        total_due = Prescription.objects.aggregate(total=Sum("med_bill_amount"))
        return round(total_due["total"], 2) if total_due["total"] else 0.00
    
    @classmethod
    def total_patients_treated(cls):
        prescriptions = Prescription.objects.all()
        treatedPatientCount = 0
        for prescription in prescriptions:
            if prescription.payment_status == "PAID":
                treatedPatientCount += 1
        return treatedPatientCount
    
    @classmethod
    def get_customer_data(cls, prescription_id):
        prescription_data = Prescription.objects.filter(prescription_id=prescription_id).values().first()
        appointment_data = PatientAppointment.objects.filter(appointment_id=prescription_data["appointment_id_id"]
                                                             ).values().first()
        return appointment_data["patient_gender"]
    
    @classmethod
    def get_total_unique_active_patients_with_age_gender_distribution(cls):
        prescriptions = Prescription.objects.all()
        totalActivePatients = []
        child = 0
        teenage = 0
        adult = 0
        male = 0
        female = 0
        undisclosed = 0
        # Active patients will be those whose are undergoing treatment
        # and have given prescription 
        # (*Only appointments will be not considered active)
        for prescription in prescriptions:
            if prescription.appointment_id:
                appointment_id = prescription.appointment_id
                appointment_data = PatientAppointment.objects.filter(appointment_id=appointment_id).values().first()
                if appointment_data["patient_social_security_ID"] not in totalActivePatients:
                    totalActivePatients.append(appointment_data["patient_social_security_ID"])
                    if appointment_data["patient_age"]:
                        if appointment_data["patient_age"] >= 0 and appointment_data["patient_age"] <= 13:
                            child += 1
                        elif appointment_data["patient_age"] >= 14 and appointment_data["patient_age"] <= 18:
                            teenage += 1
                        else:
                            adult += 1
                    if appointment_data["patient_gender"]:
                        if appointment_data["patient_gender"] == "MALE":
                            male += 1
                        elif appointment_data["patient_gender"] == "FEMALE":
                            female += 1
                        else:
                            undisclosed += 1
                        
        totalUniqueActivePatients = len(set(totalActivePatients))
        metadata = {"Children_distribution": round((child/totalUniqueActivePatients), 2), 
                    "Teenagers_distribution": round((teenage/totalUniqueActivePatients), 2), 
                    "Adults_distribution": round((adult/totalUniqueActivePatients), 2),
                    "Male_distribution": round((male/totalUniqueActivePatients), 2),
                    "Female_distribution": round((female/totalUniqueActivePatients), 2),
                    "Undisclosed_distribution": round((undisclosed/totalUniqueActivePatients), 2),
                    "total_unique_active_patients": totalUniqueActivePatients}
        return metadata
    
    
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


# Create Budget for the time period
class FinancialBudget(models.Model):
    budget_id = models.CharField(
        primary_key=True, max_length=50, editable=False, unique=True, default=None
    )
    created_by = models.CharField(max_length=100)
    budget_title = models.CharField(max_length=250, blank=True, null=True)
    budget_period_type = models.CharField(
        max_length=100,
        choices=BudgetPeriodType.choices,
        default=BudgetPeriodType.MONTHLY,
    )
    start_date = models.DateField(default=date.today)
    end_date = models.DateField(default=date.today)
    set_amount = models.DecimalField(default=150000, max_digits=10, decimal_places=2)
    approved_by = models.CharField(max_length=100, default=None, null=True, blank=True)
    evaluation_status = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        # Checking if UID exists
        if not self.budget_id:
            while True:
                new_budget_id = str("B-" + str(uuid.uuid4().hex[:5].upper()))
                if not FinancialBudget.objects.filter(budget_id=new_budget_id).exists():
                    self.budget_id = new_budget_id
                    break

        # Assigning the budget timeline
        if self.budget_period_type == BudgetPeriodType.YEARLY:
            self.start_date = date(self.start_date.year, 1, 1)
            self.end_date = date(self.start_date.year, 12, 31)
        elif self.budget_period_type == BudgetPeriodType.QUARTERLY:
            quarter_start = (self.start_date.month - 1) // 3 * 3 + 1
            self.start_date = date(self.start_date.year, quarter_start, 1)
            self.end_date = date(
                self.start_date.year, quarter_start + 2, 1
            ) + timedelta(days=89)
        elif self.budget_period_type == BudgetPeriodType.MONTHLY:
            self.start_date = date(self.start_date.year, self.start_date.month, 1)
            if self.start_date.month == 12:
                self.end_date = date(self.start_date.year + 1, 1, 1) - timedelta(days=1)
            else:
                self.end_date = date(
                    self.start_date.year, self.start_date.month + 1, 1
                ) - timedelta(days=1)

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.budget_id} - {self.budget_title}"


# Purely for creating dummy donation data
class Donations(models.Model):
    donor = models.CharField(max_length=250, null=True, blank=True)
    donation_date = models.DateTimeField()
    donation_amount = models.PositiveIntegerField(default=0)
    
    def __str__(self):
        return f"{self.donor} - {self.donation_amount}"
    


    

