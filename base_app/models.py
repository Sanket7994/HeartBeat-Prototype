# Imports
import uuid
from django.utils import timezone
from datetime import time, date, timedelta
import datetime
from school import settings
from PIL import Image
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from phonenumber_field.modelfields import PhoneNumberField
from django.core.validators import RegexValidator
from django_resized import ResizedImageField
import json
from django.core.serializers import serialize
from django.db import models


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
    avatar = ResizedImageField(
        size=[150, 150],
        default="avatar.jpg",
        upload_to="profile_avatars",
        blank=True,
        null=True,
    )
    contact_number = PhoneNumberField(
        blank=True,
        null=True,
        default=None,
        validators=[RegexValidator(r"^(\+\d{1,3})?,?\s?\d{8,15}")],
    )
    address = models.CharField(max_length=250, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    zipcode = models.IntegerField(blank=True, null=True)
    country = models.CharField(
        max_length=100, choices=Country.choices, default=None, null=True
    )
    email = models.EmailField(blank=True, null=True)
    status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    def __str__(self):
        return self.clinic_name

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
    first_name = models.CharField(max_length=100, blank=False, null=False)
    last_name = models.CharField(max_length=100, blank=False, null=False)
    avatar = ResizedImageField(
        size=[150, 150],
        default="avatar.jpg",
        upload_to="profile_avatars",
        blank=True,
        null=True,
    )
    designation = models.CharField(
        max_length=100, choices=StaffDesignation.choices, default=None, null=True
    )
    shift_type = models.CharField(
        max_length=100, choices=Shift_type.choices, default=Shift_type.GENERAL_SHIFT
    )
    email = models.EmailField(blank=True, null=True)
    contact_number = PhoneNumberField(
        default=None,
        null=True,
        blank=True,
        validators=[RegexValidator(r"^(\+\d{1,3})?,?\s?\d{8,15}")],
    )
    status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

    def save(self, *args, **kwargs):
        if not self.staff_id:
            while True:
                new_staff_id = str(uuid.uuid4().hex[:10].upper())
                if not ClinicMember.objects.filter(staff_id=new_staff_id).exists():
                    self.staff_id = new_staff_id
                    break
        super().save(*args, **kwargs)



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
        
    procedure_choice = models.CharField(choices=MyChoices.choices, default=MyChoices.OTHER, max_length=154, unique=True)
    
    def __str__(self):
        return self.procedure_choice


# Create appointments
class PatientAppointment(models.Model):
    class StatusCode(models.TextChoices):
        APPROVED = ("APPROVED", "Approved")
        PENDING = ("PENDING", "Pending")
        CANCELLED = ("CANCELLED", "Cancelled")

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
    patient_first_name = models.CharField(max_length=150)
    patient_last_name = models.CharField(max_length=150, null=False, blank=False)
    gender = models.CharField(
        max_length=100, choices=Gender.choices, default=None, null=True
    )
    date_of_birth = models.DateField(blank=True, null=True)
    patient_age = models.IntegerField(blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    contact_number = PhoneNumberField(
        blank=True,
        null=True,
        validators=[RegexValidator(r"^(\+\d{1,3})?,?\s?\d{8,15}")],
        default=None,
    )
    recurring_patient = models.BooleanField(default=False)
    procedures = models.ManyToManyField(MedicalProceduresTypes)
    appointment_date = models.DateField(
        validators=[validate_date, validate_weekday],
        default=timezone.now,
    )
    appointment_slot = models.CharField(blank=False, max_length=50)
    status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    def __str__(self):
        return self.appointment_id

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

        if not self.appointment_id:
            while True:
                new_appointment_id = str(uuid.uuid4().hex[:10].upper())
                if not PatientAppointment.objects.filter(
                    appointment_id=new_appointment_id
                ).exists():
                    self.appointment_id = new_appointment_id
                    break
        super().save(*args, **kwargs)


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
        ANALGESICS = ("ANALGESICS","ANALGESICS: Used for headaches, muscle pain, toothaches, menstrual pain",)
        ANTIPYRETICS = "ANTIPYRETICS", "ANTIPYRETICS: Used to reduce fever"
        ANTACIDS = "ANTACIDS", "ANTACIDS: Used for heartburn, indigestion, acid reflux"
        ANTIHISTAMINES = ("ANTIHISTAMINES", "ANTIHISTAMINES: Used for allergies, itchy skin or eyes, sneezing, runny nose",)
        COUGH_AND_COLD = ("COUGH_AND_COLD", "COUGH_AND_COLD: Used for cough relief, nasal congestion, sore throat",)
        TOPICAL_ANALGESICS = ("TOPICAL_ANALGESICS", "TOPICAL_ANALGESICS: Used for muscle aches and strains, joint pain, minor injuries",)
        ANTIDIARRHEALS = "ANTIDIARRHEALS", "ANTIDIARRHEALS: Used for diarrhea relief"
        DERMATOLOGICAL = ("DERMATOLOGICAL", "DERMATOLOGICAL: Used for acne treatment, eczema or dermatitis management, fungal infections",)
        ORAL_CONTRACEPTIVES = ("ORAL_CONTRACEPTIVES", "ORAL_CONTRACEPTIVES: Used for pregnancy prevention",)
        OPHTHALMIC = ("OPHTHALMIC","OPHTHALMIC: Used for eye infections, dry eyes, allergic conjunctivitis",)
        OTHER = ("OTHER", "Other")

    drug_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,)
    drug_name = models.CharField(max_length=250, unique=True)
    generic_name = models.CharField(max_length=250)
    brand_name = models.CharField(max_length=250)
    drug_class = models.CharField(choices=GeneralDrugClass.choices, default=GeneralDrugClass.OTHER, max_length=250,)
    dosage_form = models.CharField(choices=DosageType.choices, default=DosageType.OTHER, max_length=250,)
    unit_price = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    add_quantity = models.PositiveIntegerField(default=0, help_text="add_quantity")
    total_stock_quantity = models.PositiveIntegerField(default=0, editable=False, help_text="main_stock_quantity")
    manufacture_date = models.DateField(default=timezone.now)
    lifetime_in_months = models.PositiveIntegerField(default=0, help_text="number_of_months")
    expiry_date = models.DateField(default=None, blank=True, null=True, editable=False)
    added_at = models.DateTimeField(auto_now_add=True, editable=False)

    def save(self, *args, **kwargs):
        # Update Stock If new quantity is added
        if self.add_quantity:
            new_stock = int(self.total_stock_quantity) + int(self.add_quantity)
            self.total_stock_quantity = new_stock

        # Add expiry date and
        if self.manufacture_date and self.lifetime_in_months:
            expiry_date = self.manufacture_date + timedelta(days=30 * self.lifetime_in_months)
            self.expiry_date = expiry_date

        # Generate ID
        if not self.drug_id:
            while True:
                new_drug_id = str("MED-" + str(uuid.uuid4().hex[:10].upper()))
                if not PharmacyInventory.objects.filter(drug_id=new_drug_id).exists():
                    self.drug_id = new_drug_id
                    break
        super().save(*args, **kwargs)

    def __str__(self):
        return self.drug_name


# Allot medicines to client on Prescription

class PrescribedMedication(models.Model):
    class DosingFrequency(models.TextChoices):
        ONCE_A_DAY = "ONCE_A_DAY", "Once a day"
        TWICE_A_DAY = "TWICE_A_DAY", "Twice a day"
        THRICE_A_DAY = "THRICE_A_DAY", "Thrice a day"
        FLEXIBLE = "FLEXIBLE", "Flexible timings"

    for_prescription = models.ForeignKey('Prescription', on_delete=models.SET_NULL, null=True)
    medicine = models.ForeignKey(PharmacyInventory, on_delete=models.SET_NULL, null=True)
    quantity = models.PositiveIntegerField(default=0)
    dosage_freq = models.CharField(
        choices=DosingFrequency.choices,
        default=DosingFrequency.FLEXIBLE,
        max_length=250,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    ordering = ["-created_at"]

    def __str__(self):
        return f"Related to Prescription: {self.for_prescription.prescription_id}"


# Patient`s Prescription Model
class Prescription(models.Model):
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
    medications = models.ManyToManyField(
        "PrescribedMedication",
        related_name="prescriptions",
    )
    description = models.TextField(max_length=300, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    def save(self, *args, **kwargs):
        
        if not self.medications:
            medications_dict = self.medications
            serialized_medications = []
            for medication in medications_dict:
                prescribed_med_dict = PrescribedMedication.objects.all(id=medication)
                serialized_medications.append(prescribed_med_dict)
                self.medications = serialized_medications
                
        if not self.prescription_id:
            while True:
                new_prescription_id = str("P-" + str(uuid.uuid4().hex[:10].upper()))
                if not Prescription.objects.filter(
                    prescription_id=new_prescription_id
                ).exists():
                    self.prescription_id = new_prescription_id
                    break
        super().save(*args, **kwargs)

    def __str__(self):
        return str(self.prescription_id)



