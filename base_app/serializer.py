import string
from rest_framework import serializers
from .models import *

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


# Task Manager
class TaskAssignmentManagerSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()
    class Meta:
        model = TaskAssignmentManager
        fields = "__all__"


class PersonalJournalSerializer(serializers.ModelSerializer):
    created_on = serializers.ReadOnlyField()
    class Meta:
        model = PersonalJournal
        fields = "__all__"


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


class ClientDataCollectionPoolSerializer(serializers.ModelSerializer):
    profile_created_at = serializers.ReadOnlyField()
    
    class Meta:
        model = ClientDataCollectionPool
        fields = "__all__"



# Drug Inventory Information
class PharmacyInventorySerializer(serializers.ModelSerializer):
    added_at = serializers.ReadOnlyField()
    class Meta:
        model = PharmacyInventory
        fields = "__all__"
        
        
# Purchase order for Drug
class PurchaseOrderSerializer(serializers.ModelSerializer):
    request_sent_at = serializers.ReadOnlyField()
    class Meta:
        model = PurchaseOrder
        fields = "__all__"


# Prescription Information
class PrescriptionSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()

    class Meta:
        model = Prescription
        fields = (
            "prescription_id",
            "clinic_name",
            "consultant",
            "appointment_id",
            "stripe_client_id",
            "medications_json",
            "shipping_address",
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


# Star Rating feedback     
class ClientServiceFeedbackSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()
    class Meta:
        model = ClientServiceFeedback
        fields = ['customer_id', 'overall_rating', 'comment', 'created_at']