# Imports
import uuid
import stripe
import json
from decimal import Decimal
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
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from phonenumber_field.modelfields import PhoneNumberField
from django.core.validators import RegexValidator
from django_resized import ResizedImageField
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
        return self.clinic_name
    
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
        return f"{self.staff_first_name} {self.staff_last_name}"

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
        ANALGESICS = ("ANALGESICS: Used for headaches, muscle pain, toothaches, menstrual pain", "ANALGESICS")
        ANTIPYRETICS = ("ANTIPYRETICS: Used to reduce fever", "ANTIPYRETICS")
        ANTACIDS = ("ANTACIDS: Used for heartburn, indigestion, acid reflux", "ANTACIDS")
        ANTIHISTAMINES = ("ANTIHISTAMINES: Used for allergies, itchy skin or eyes, sneezing, runny nose", "ANTIHISTAMINES")
        COUGH_AND_COLD = ("COUGH AND COLD: Used for cough relief, nasal congestion, sore throat", "COUGH_AND_COLD")
        TOPICAL_ANALGESICS = ("TOPICAL ANALGESICS: Used for muscle aches and strains, joint pain, minor injuries", "TOPICAL_ANALGESICS")
        ANTIDIARRHEALS = ("ANTIDIARRHEALS: Used for diarrhea relief", "ANTIDIARRHEALS")
        DERMATOLOGICAL = ("DERMATOLOGICAL: Used for acne treatment, eczema or dermatitis management, fungal infections", "DERMATOLOGICAL")
        ORAL_CONTRACEPTIVES = ("ORAL CONTRACEPTIVES: Used for pregnancy prevention", "ORAL_CONTRACEPTIVES")
        OPHTHALMIC = ("OPHTHALMIC: Used for eye infections, dry eyes, allergic conjunctivitis", "OPHTHALMIC")
        OTHER = ("Other", "OTHER")
        
    class UnitType(models.TextChoices):
        SINGLE_UNIT = "SINGLE_UNIT", "Single Unit"
        PACK_OF_10 = "PACK_OF_10", "Pack of 10"
        PACK_OF_50 = "PACK_OF_50", "Pack of 50"

    drug_id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,)
    
    stripe_product_id = models.CharField(max_length=255, blank=True, null=True, editable=False)
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
    drug_class = models.CharField(choices=GeneralDrugClass.choices, default=GeneralDrugClass.OTHER, max_length=250,)
    dosage_form = models.CharField(choices=DosageType.choices, default=DosageType.OTHER, max_length=250,)
    unit_type = models.CharField(choices=UnitType.choices, default=UnitType.SINGLE_UNIT, max_length=250,)
    price = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    stripe_price_id = models.CharField(max_length=255, blank=True, null=True, editable=False)
    add_new_stock = models.PositiveIntegerField(default=0, help_text="add_quantity")
    stock_available = models.PositiveIntegerField(default=0, editable=False, help_text="available_stock")
    stock_history = models.TextField(default="[]", editable=False, help_text="stock history")
    manufacture_date = models.DateField(default=timezone.now)
    lifetime_in_months = models.PositiveIntegerField(default=0, help_text="number_of_months")
    expiry_date = models.DateField(default=None, blank=True, null=True, editable=False)
    added_at = models.DateTimeField(auto_now_add=True, editable=False)

    def save(self, *args, **kwargs):
        # Update Stock If new quantity is added
        if self.add_new_stock:
            new_stock = int(self.stock_available) + int(self.add_new_stock)
            self.stock_available = new_stock
            # Store the new entry in stock_history
            stock_history = json.loads(self.stock_history)
            new_entry = {'quantity': self.add_new_stock, 'date': f"{datetime.now():%d-%m-%Y %H:%M:%S}"}
            stock_history.append(new_entry)
            self.stock_history = json.dumps(stock_history)
            # Reset add_new_stock to default value
            self.add_new_stock = 0  

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
                currency='usd'  # Change to your desired currency
            )
            self.stripe_price_id = price.id

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
    purpose = models.CharField(max_length=250, blank=True, null=True, editable=False)
    amount_per_unit = models.DecimalField(default=0, max_digits=10, decimal_places=2, editable=False)
    quantity = models.PositiveIntegerField(default=0)
    total_payable_amount = models.DecimalField(default=0, max_digits=10, decimal_places=2, editable=False)
    dosage_freq = models.CharField(
        choices=DosingFrequency.choices,
        default=DosingFrequency.FLEXIBLE,
        max_length=250,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if self.medicine:
            self.amount_per_unit = self.medicine.price
        if self.medicine:
            self.purpose = self.medicine.drug_class
        if self.medicine:
            self.total_payable_amount = self.amount_per_unit * self.quantity
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Related to Prescription: {self.for_prescription.prescription_id}"


# Patient`s Prescription Model
class Prescription(models.Model):
    class StatusCode(models.TextChoices):
        APPROVED = ("APPROVED", "Approved")
        PENDING = ("PENDING", "Pending")
        CANCELLED = ("CANCELLED", "Cancelled")
        
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
    stripe_appointment_service_id = models.CharField(max_length=250, blank=True, null=True)
    stripe_appointment_price_id = models.CharField(max_length=250, blank=True, null=True)
    appointment_fee = models.DecimalField(default=0, max_digits=10, decimal_places=2, editable=False)
    med_bill_amount = models.DecimalField(default=0, max_digits=10, decimal_places=2, editable=False)
    coupon_discount = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    grand_total = models.DecimalField(default=0, max_digits=10, decimal_places=2, editable=False)
    description = models.TextField(max_length=300, blank=True, null=True)
    approval_status = models.CharField(max_length=100, choices=StatusCode.choices, default=StatusCode.PENDING)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    def save(self, *args, **kwargs):
        if not self.medications.exists():
            medications_dict = self.medications.values_list("id", flat=True)
            serialized_medications = []
            for medication_id in medications_dict:
                prescribed_med = PrescribedMedication.objects.get(id=medication_id)
                serialized_medications.append(prescribed_med)
            self.medications.set(serialized_medications)

        if self.medications.exists():
            total_med_amount = 0
            for medicine in self.medications.all():
                amount = Decimal(str((medicine.total_payable_amount)))
                total_med_amount += amount
            # Adding appointment charge
            self.appointment_fee = 100
            self.med_bill_amount = total_med_amount
            self.grand_total = (self.med_bill_amount + self.appointment_fee) - self.coupon_discount

        if not self.prescription_id:
            while True:
                new_prescription_id = str("P-" + str(uuid.uuid4().hex[:10].upper()))
                if not Prescription.objects.filter(prescription_id=new_prescription_id).exists():
                    self.prescription_id = new_prescription_id
                    break
        
        # Create Stripe product and price if IDs are not set
        if not self.stripe_appointment_service_id:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            product = stripe.Product.create(name="Appointment Fee")
            self.stripe_appointment_service_id = product.id

        if not self.stripe_appointment_price_id:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            price = stripe.Price.create(
                product = self.stripe_appointment_service_id,
                unit_amount = int(self.appointment_fee * 100),  # Stripe expects the amount in cents
                currency = 'usd'  
            )
            self.stripe_appointment_price_id = price.id
        super().save(*args, **kwargs)

    def __str__(self):
        return str(self.prescription_id)
    
    
    
# class ClientPaymentStatus(models.Model):
#     prescription_id = models.ForeignKey(Prescription, on_delete=models.SET_NULL, null=True, related_name="prescription_receipt_id",)
#     stripe_session_id = models.CharField(max_length=250, editable=False)
#     stripe_payment_intent = models.CharField(max_length=250, editable=False)
#     stripe_payment_method_types = models.CharField(max_length=250, editable=False)
#     stripe_payment_status = models.CharField(max_length=250, editable=False)
    
#     def save(self, *args, **kwargs):
#         if not self.stripe_session_id:
            
    
