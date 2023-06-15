import string
from rest_framework import serializers
from .models import CustomUser, Clinic, ClinicMember, PatientAppointment, Prescription, PharmacyInventory

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
            or len(otp) != 8
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
            "user",
            "contact_number",
            "email",
            "address",
            "city",
            "zipcode",
            "country",
            "status",
            "created_at",
        )


# Clinic Staff Member
class ClinicStaffSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()

    class Meta:
        model = ClinicMember
        fields = (
            "staff_id",
            "clinic_name",
            "first_name",
            "last_name",
            "email",
            "designation",
            "shift_type",
            "status",
            "created_at",
        )


# Appointment Information
class AppointmentSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()

    class Meta:
        model = PatientAppointment
        fields = "__all__"

# Drug Inventory Information
class PharmacyInventorySerializer(serializers.ModelSerializer):
    added_at = serializers.ReadOnlyField()

    class Meta:
        model = PharmacyInventory
        fields = (
            "drug_id",
            "drug_name",
            "generic_name",
            "brand_name",
            "drug_class",
            "dosage_form",
            "unit_price",
            "quantity",
            "manufacture_date",
            "lifetime_in_months",
            "expiry_date",
            "added_at",
        )
        
# Drug Inventory Information
class PrescriptionSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()

    class Meta:
        model = Prescription
        fields = (
            "prescription_id",
            "clinic_name",
            "consultant",
            "appointment_id",
            "patient_first_name",
            "patient_last_name",
            "age",
            "medication",
            "dosage_freq",
            "quantity",
            "description",
            "created_at",
        )

