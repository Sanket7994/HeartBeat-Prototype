import string
from rest_framework import serializers
from .models import (
    CustomUser,
    Clinic,
    ClinicMember,
    MedicalProceduresTypes,
    PatientAppointment,
    Prescription,
    PharmacyInventory,
    PrescribedMedicationModel,
    ClientPaymentData,
)

# To convert the Model object to an API-appropriate format like JSON,
# Django REST framework uses the ModelSerializer class to convert any model to serialized JSON objects:


# User
class CustomSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()

    class Meta:
        model = CustomUser
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "select_role",
            "avatar",
            "created_at",
        )
        extra_kwargs = {"password": {"write_only": True}}


# Verify OTP
class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=8)

    def validate_otp(self, otp):
        if (
            not all(c in string.ascii_letters + string.digits for c in otp)
            or len(otp) != 6
        ):
            raise serializers.ValidationError("Invalid OTP format.")
        return otp


# Forgot password authentication
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


# Reset password authentication with validation
class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs


# Clinic Information
class ClinicSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()

    class Meta:
        model = Clinic
        fields = (
            "clinic_id",
            "clinic_name",
            "clinic_logo",
            "user",
            "clinic_contact_number",
            "clinic_email",
            "clinic_address",
            "clinic_city",
            "clinic_zipcode",
            "clinic_country",
            "clinic_status",
            "created_at",
        )


# Clinic Staff Member
class ClinicStaffSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()

    class Meta:
        model = ClinicMember
        fields = (
            "staff_id",
            "staff_first_name",
            "staff_last_name",
            "staff_avatar",
            "clinic_name",
            "staff_contact_number",
            "staff_email",
            "staff_designation",
            "shift_type",
            "staff_status",
            "created_at",
        )


# Choices for appointment related medical procedures
class MedicalProceduresTypesSerializer(serializers.ModelSerializer):
    class Meta:
        model = MedicalProceduresTypes
        depth = 1
        fields = ("procedure_choice",)


# Appointment model serializer
class AppointmentSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()
    procedures = serializers.SerializerMethodField()

    class Meta:
        model = PatientAppointment
        fields = "__all__"

    def get_procedures(self, obj):
        return [procedure.procedure_choice for procedure in obj.procedures.all()]


# Drug Inventory Information
class PharmacyInventorySerializer(serializers.ModelSerializer):
    added_at = serializers.ReadOnlyField()

    class Meta:
        model = PharmacyInventory
        fields = "__all__"


# Prescribed medical information with quality
class PrescribedMedicationModelSerializer(serializers.ModelSerializer):
    medicine_name = serializers.CharField(source="medicine.drug_name")
    prescription_id = serializers.CharField(source="for_prescription.prescription_id")

    class Meta:
        model = PrescribedMedicationModel
        depth = 1
        fields = (
            "for_prescription_id",
            "medicine_id",
            "medicine_name",
            "purpose",
            "quantity",
            "amount_per_unit",
            "total_payable_amount",
            "dosage_freq",
        )


# Prescription Information
class PrescriptionSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()
    medications = PrescribedMedicationModelSerializer(many=True)

    class Meta:
        model = Prescription
        fields = (
            "prescription_id",
            "clinic_name",
            "consultant",
            "appointment_id",
            "medications",
            "stripe_appointment_service_id",
            "stripe_appointment_price_id",
            "appointment_fee",
            "med_bill_amount",
            "coupon_discount",
            "grand_total",
            "description",
            "approval_status",
            "payment_status",
            "created_at",
        )


# Payment serialization
class ClientPaymentDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientPaymentData
        fields = ['prescription_id', 'session_id', 'payment_intent', 'payment_method',
                  'client_billing_address', 'stripe_session_status', 'stripe_payment_status',
                  'session_created_on', 'session_expired_on']
        
    def update(self, instance, validated_data):
        if self.context['request'].method == 'PUT':
            raise serializers.ValidationError("Updating existing instances is not allowed.")
        return super().update(instance, validated_data)
