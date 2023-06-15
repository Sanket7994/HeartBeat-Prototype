# Imports
import uuid
from django.utils import timezone
from datetime import time
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
    avatar = models.ImageField(default="avatar.jpg", upload_to="profile_avatars")
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
        # save the profile
        super().save(*args, **kwargs)

        # resize the profile image first
        img = Image.open(self.avatar.path)
        if img.height > 150 or img.width > 150:
            output_size = (150, 150)
            # create a thumbnail
            img.thumbnail(output_size)
            # overwrite the larger image
            img.save(self.avatar.path)

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
    avatar = models.ImageField(default="avatar.jpg", upload_to="profile_avatars")
    contact_number = PhoneNumberField(
        blank=True,
        null=True,
        default=None,
        validators=[RegexValidator(r"^(\+\d{1,3})?,?\s?\d{8,15}")],
    )
    address = models.CharField(max_length=250, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(
        max_length=100, choices=Country.choices, default=None, null=True
    )
    email = models.EmailField(blank=True, null=True)
    status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

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

    def save(self, *args, **kwargs):
        # save the profile
        super().save(*args, **kwargs)

        # resize the profile image first
        img = Image.open(self.avatar.path)
        if img.height > 150 or img.width > 150:
            output_size = (150, 150)
            # create a thumbnail
            img.thumbnail(output_size)
            # overwrite the larger image
            img.save(self.avatar.path)

    def __str__(self):
        return self.clinic_name


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
    avatar = models.ImageField(default="avatar.jpg", upload_to="profile_avatars")
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
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.staff_id:
            while True:
                new_staff_id = str(uuid.uuid4().hex[:10].upper())
                if not ClinicMember.objects.filter(staff_id=new_staff_id).exists():
                    self.staff_id = new_staff_id
                    break
        super().save(*args, **kwargs)

    def save(self, *args, **kwargs):
        # save the profile
        super().save(*args, **kwargs)

        # resize the profile image first
        img = Image.open(self.avatar.path)
        if img.height > 150 or img.width > 150:
            output_size = (150, 150)
            # create a thumbnail
            img.thumbnail(output_size)
            # overwrite the larger image
            img.save(self.avatar.path)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


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

    def validate_weekday(self):
        if (
            self.appointment_date.weekday() >= 5): 
            raise ValidationError(_("Appointments are not available on weekends"))

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
    email = models.EmailField(blank=True, null=True)
    contact_number = PhoneNumberField(
        blank=True,
        null=True,
        validators=[RegexValidator(r"^(\+\d{1,3})?,?\s?\d{8,15}")],
        default=None,
    )
    recurring_patient = models.BooleanField(default=False)
    procedures = models.CharField(max_length=255, default=list, blank=True, null=True)
    appointment_date = models.DateField(
        validators=[validate_date, validate_weekday],
        default=timezone.now,
    )
    appointment_slot = models.CharField(blank=False, max_length=50)
    status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.appointment_id:
            while True:
                new_appointment_id = str(uuid.uuid4().hex[:10].upper())
                if not PatientAppointment.objects.filter(
                    appointment_id=new_appointment_id
                ).exists():
                    self.appointment_id = new_appointment_id
                    break
        super().save(*args, **kwargs)

    def __str__(self):
        return self.appointment_id
