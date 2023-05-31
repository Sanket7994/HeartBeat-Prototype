import uuid
from django.utils import timezone
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
        max_length=100, choices=Roles.choices, default=Roles.OPERATOR
    )

    id = models.CharField(unique=True, primary_key=True, max_length=50, editable=False)
    email = models.EmailField(unique=True, blank=False, null=False)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    avatar = models.ImageField(default="avatar.jpg", upload_to="profile_avatars")
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_operator = models.BooleanField(default=False)
    is_clinic_management = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    # def save(self, *args, **kwargs):
    #     # save the profile
    #     super().save(*args, **kwargs)

    #     # resize the profile image first
    #     img = Image.open(self.avatar.path)
    #     if img.height > 200 or img.width > 200:
    #         output_size = (200, 200)
    #         # create a thumbnail
    #         img.thumbnail(output_size)
    #         # overwrite the larger image
    #         img.save(self.avatar.path)

    # def save_user_uid(self, *args, **kwargs):
    #     if not self.id:
    #         while True:
    #             # Give Unique ID as per designation of the user
    #             if self.is_admin:
    #                 new_id = str("BA-" + str(uuid.uuid4().hex[:10].upper()))
    #             elif self.is_operator:
    #                 new_id = str("OP-" + str(uuid.uuid4().hex[:10].upper()))
    #             elif self.is_clinic_management:
    #                 new_id = str("CM-" + str(uuid.uuid4().hex[:10].upper()))
    #             # If user doesn`t exit in database give him a new id
    #             if not CustomUser.objects.filter(id=new_id).exists():
    #                 self.id = new_id
    #                 break
    #     super().save(*args, **kwargs)
        

# Clinic Model
class Clinic(models.Model):
    class Country(models.TextChoices):
        UK = ("UK", "UNITED KINGDOM")
        IN = ("IN", "INDIA")
        US = ("US", "UNITED STATES OF AMERICA")
        ES = ("ES", "SPAIN")
        CA = ("CA", "CANADA")
        CN = ("CN", "CHINA")

    class StatusCode(models.TextChoices):
        APPROVED = ("APPROVED", "Approved")
        PENDING = ("PENDING", "Pending")

    clinic_id = models.CharField(
        default=str(uuid.uuid4().hex[:10].upper()),
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    email = models.EmailField(blank=True, null=True)
    clinic_name = models.CharField(max_length=100, blank=False, null=False)
    contact_number = models.CharField(max_length=50, blank=True)
    address = models.CharField(max_length=250)
    city = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, choices=Country.choices, default=None)
    status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

    def __str__(self):
        return self.clinic_name

    def save(self, *args, **kwargs):
        if not self.clinic_id:
            while True:
                # Generate a unique clinic_id
                new_clinic_id = str(uuid.uuid4().hex[:10].upper())
                if not Clinic.objects.filter(clinic_id=new_clinic_id).exists():
                    self.clinic_id = new_clinic_id
                    break
        super().save(*args, **kwargs)

    def save(self, *args, **kwargs):
        if self.status == None:
            self.status = self.StatusCode.PENDING
        elif self.status == "":
            self.status = self.StatusCode.PENDING
        super().save(*args, **kwargs)


# clinic Members
class ClinicMember(models.Model):
    class StaffRoles(models.TextChoices):
        IVF_COORDINATOR = ("IVF_COORDINATOR", "IVF Coordinator")
        DONOR_COORDINATOR = ("DONOR_COORDINATOR", "Donor Coordinator")
        RECEPTIONIST = ("RECEPTIONIST", "Receptionist")
        DOCTOR_PHYSICIST = ("DOCTOR_PHYSICIST", "Doctor/Physicist")
        EMBRYOLOGY = ("EMBRYOLOGY", "Embryology")
        NURSE = ("NURSE", "Nurse")
        LABORATORY = ("LABORATORY", "Laboratory")
        PSYCHOLOGIST_COUNSELLOR = ("PSYCHOLOGIST_COUNSELLOR", "Psychologist/Counsellor")

    class StatusCode(models.TextChoices):
        ACTIVE = ("ACTIVE", "Active")
        PENDING = ("PENDING", "Pending")

    staff_id = models.CharField(
        default=str(uuid.uuid4().hex[:7].upper()),
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    clinic_name = models.ForeignKey(Clinic, on_delete=models.CASCADE, blank=False)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    designation = models.CharField(
        max_length=100, choices=StaffRoles.choices, default=None
    )
    email = models.EmailField(blank=True, null=True)
    status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

    def save(self, *args, **kwargs):
        if not self.staff_id:
            while True:
                # Generate a unique staff_id
                new_staff_id = str(uuid.uuid4().hex[:7].upper())
                if not Clinic.objects.filter(staff_id=new_staff_id).exists():
                    self.staff_id = new_staff_id
                    break
        super().save(*args, **kwargs)

    def save(self, *args, **kwargs):
        if self.status == None:
            self.status = self.StatusCode.PENDING
        elif self.status == "":
            self.status = self.StatusCode.PENDING
        super().save(*args, **kwargs)


# Add Appointment information
class PatientAppointment(models.Model):
    class StatusCode(models.TextChoices):
        APPROVED = ("APPROVED", "Approved")
        PENDING = ("PENDING", "Pending")
        CANCELLED = ("CANCELLED", "Cancelled")

    def validate_date(value):
        if value < timezone.now().date():
            raise ValidationError(_("Invalid date."))

    appointment_id = models.CharField(
        default=str(uuid.uuid4().hex[:12].upper()),
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
    recipient = models.ForeignKey(ClinicMember, on_delete=models.CASCADE, default=None)
    patient_full_name = models.CharField(max_length=150, null=False, blank=False)
    email = models.EmailField(blank=True, null=True)
    contact_number = models.CharField(max_length=50)
    appointment_date = models.DateField(
        validators=[validate_date],
        default=timezone.now,
    )
    appointment_slot = models.CharField(blank=False, max_length=50)
    status = models.CharField(
        max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

    def __str__(self):
        return self.appointment_id

    def save(self, *args, **kwargs):
        if not self.appointment_id:
            while True:
                # Generate a unique appointment_id
                new_appointment_id = str(uuid.uuid4().hex[:5].upper())
                if not Clinic.objects.filter(
                    appointment_id=new_appointment_id
                ).exists():
                    self.appointment_id = new_appointment_id
                    break
        super().save(*args, **kwargs)

    def save(self, *args, **kwargs):
        if self.status == None:
            self.status = self.StatusCode.PENDING
        elif self.status == "":
            self.status = self.StatusCode.PENDING
        super().save(*args, **kwargs)


# Add drug information
class Drug(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True)
    drug_id = models.CharField(
        primary_key=True,
        default=str(uuid.uuid4().hex[:10].upper()),
        max_length=50,
        editable=False,
        unique=True,
    )
    drug_name = models.CharField(max_length=200, unique=True, blank=False, null=False)
    company = models.CharField(max_length=200)
    generic_name = models.CharField(max_length=200)
    quantity = models.IntegerField(blank=False, null=False)
    unit_price = models.FloatField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.drug_name
