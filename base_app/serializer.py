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
    PrescribedMedication,
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


# Choices for appointment related medical procedures
class MedicalProceduresTypesSerializer(serializers.ModelSerializer):
    class Meta:
        model = MedicalProceduresTypes
        fields = ('procedure_choice',)


# Appointment model serializer
class AppointmentSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()
    procedures = serializers.SerializerMethodField()  
    class Meta:
        model = PatientAppointment
        fields = '__all__'

    def get_procedures(self, obj):
        return [procedure.procedure_choice for procedure in obj.procedures.all()]


# Drug Inventory Information
class PharmacyInventorySerializer(serializers.ModelSerializer):
    added_at = serializers.ReadOnlyField()

    class Meta:
        model = PharmacyInventory
        fields = "__all__"



# Prescribed medical information with quality
class PrescribedMedicationSerializer(serializers.ModelSerializer):
    medicine_name = serializers.CharField(source="medicine.drug_name")
    prescription_id = serializers.CharField(source="for_prescription.prescription_id")
    class Meta:
        model = PrescribedMedication
        depth = 1
        fields = ("prescription_id", "medicine_id", "medicine_name", "quantity", "dosage_freq") 


# Prescription Information
class PrescriptionSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()
    medications = PrescribedMedicationSerializer(many=True)
    class Meta:
        model = Prescription
        fields = (
            "prescription_id",
            "clinic_name",
            "consultant",
            "appointment_id",
            "medications",
            "description",
            "created_at",
        )



