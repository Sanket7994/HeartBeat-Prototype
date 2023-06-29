    # Imports
import uuid
import stripe
from decimal import Decimal
from django.conf import settings 
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.db import models
from models import PharmacyInventory, Clinic, ClinicMember, PatientAppointment






class Prescription(models.Model):
    class StatusCode(models.TextChoices):
        APPROVED = ("APPROVED", "Approved")
        PENDING = ("PENDING", "Pending")
        CANCELLED = ("CANCELLED", "Cancelled")
        
    prescription_id = models.ForeignKey('PrescribedMedication', on_delete=models.SET_NULL, null=True, related_name='for_prescription')
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
        'PrescribedMedication',
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
    payment_status = models.CharField(max_length=100, default="unpaid")
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    def save(self, *args, **kwargs):
        if not self.medications.exists():
            medications_dict = self.medications.values_list("id", flat=True)
            serialized_medications = []
            for medication_id in medications_dict:
                model = 'PrescribedMedication'
                prescribed_med = model.objects.get(id=medication_id)
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

        if not self.stripe_appointment_service_id:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            product = stripe.Product.create(name="Appointment Fee")
            self.stripe_appointment_service_id = product.id

        if not self.stripe_appointment_price_id:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            price = stripe.Price.create(
                product=self.stripe_appointment_service_id,
                unit_amount=int(self.appointment_fee * 100),  # Stripe expects the amount in cents
                currency='usd'
            )
            self.stripe_appointment_price_id = price.id

        super().save(*args, **kwargs)

    def __str__(self):
        return str(self.prescription_id)
    
    
# Allot medicines to client on Prescription
class PrescribedMedication(models.Model):
    class DosingFrequency(models.TextChoices):
        ONCE_A_DAY = "ONCE_A_DAY", "Once a day"
        TWICE_A_DAY = "TWICE_A_DAY", "Twice a day"
        THRICE_A_DAY = "THRICE_A_DAY", "Thrice a day"
        FLEXIBLE = "FLEXIBLE", "Flexible timings"
        
    for_prescription = models.CharField(
        primary_key=True,
        max_length=50,
        editable=False,
        unique=True,
    )
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
            
        # Updating unique identifier
        if not self.for_prescription:
            while True:
                new_for_prescription = str("P-" + str(uuid.uuid4().hex[:10].upper()))
                if not Prescription.objects.filter(for_prescription=new_for_prescription).exists():
                    self.for_prescription = new_for_prescription
                    break
                
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Related to Prescription: {self.for_prescription}"
    


