from rest_framework import fields, serializers
from .models import (
    CustomUser,
    Clinic,
    Drug,
    ClinicMember,
    PatientAppointment,
    MedicalProcedure,
)

# To convert the Model object to an API-appropriate format like JSON,
# Django REST framework uses the ModelSerializer class to convert any model to serialized JSON objects:


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
            "created_at",
        )
        extra_kwargs = {"password": {"write_only": True}}


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
            "contact_number",
            "address",
            "city",
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
            "status",
            "created_at",
        )


class MedicalProcedureSerializer(serializers.ModelSerializer):
    class Meta:
        model = MedicalProcedure
        fields = "__all__"


# Appointment Information
class AppointmentSerializer(serializers.ModelSerializer):
    procedures = serializers.PrimaryKeyRelatedField(
        queryset=MedicalProcedure.objects.all(), many=True
    )
    created_at = serializers.ReadOnlyField()

    class Meta:
        model = PatientAppointment
        fields = "__all__"


# Drug Information
class DrugSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()

    class Meta:
        model = Drug
        fields = (
            "drug_id",
            "user",
            "drug_name",
            "company",
            "generic_name",
            "quantity",
            "unit_price",
            "created_at",
        )
