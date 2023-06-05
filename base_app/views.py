# Within the project directory
from .models import (
    CustomUser,
    Clinic,
    Drug,
    ClinicMember,
    PatientAppointment,
    MedicalProcedure,
)
from .serializer import (
    ClinicSerializer,
    DrugSerializer,
    CustomSerializer,
    ClinicStaffSerializer,
    AppointmentSerializer,
    MedicalProcedureSerializer
)
from .emails import (
    send_email_notification,
    send_forget_password_mail,
    send_user_profile_update_notification,
    send_user_profile_delete_notification,
)
from .serializer import ForgotPasswordSerializer, ResetPasswordSerializer
from .filter import filter_queryset

# External REST libraries and models

from rest_framework import status
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken,
    BlacklistedToken,
)

# External Django libraries and modules
from datetime import timedelta
from django.dispatch import Signal
from django.core.paginator import Paginator, EmptyPage
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator


class PingView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response(
            data={"user": request.data.get("email"), "message": "Server is running"}
        )


# User Account creation API
class SignupView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            email = request.data.get("email")
            first_name = request.data.get("first_name")
            last_name = request.data.get("last_name")
            password = request.data.get("password")
            select_role = request.data.get("select_role")

            is_email_exits = CustomUser.objects.filter(email=email)
            # Error case handling for User
            if is_email_exits.exists():
                return Response(
                    data={"message": "Email already exits"},
                    status=status.HTTP_403_FORBIDDEN,
                )

            if select_role == "OPERATOR":
                is_operator = True
                is_clinic_management = False
            elif select_role == "CLINIC_MANAGEMENT":
                is_operator = False
                is_clinic_management = True
            else:
                return Response(status=status.HTTP_400_BAD_REQUEST)

            user = CustomUser(
                email=email,
                first_name=first_name,
                last_name=last_name,
                select_role=select_role,
                is_operator=is_operator,
                is_clinic_management=is_clinic_management,
            )
            user.set_password(password)
            user.save()
            # Sending Account activation notification email
            send_email_notification([user])
            return Response(
                data={
                    "message": "Account has been created and sent notification Successfully, Kindly Check."
                },
                status=status.HTTP_201_CREATED,
            )
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# User Account Login API
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get("email")
            password = request.data.get("password")
            remember_me = request.data.get("remember_me")

            # Rain check from user database
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response(
                    {"message": "User with this email does not exist."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Authentication
            user = authenticate(request, email=email, password=password)
            # Error Case
            if user is None:
                return Response(
                    data={"message": "Email or Password is incorrect"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            elif password is None:
                return Response(
                    data={"message": "Enter the password to login!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Login the user
            login(request, user)

            # Generate tokens
            refresh_token = RefreshToken.for_user(user)

            if remember_me == "True":
                # Set token expiration to a longer duration if "Remember Me" is checked
                refresh_token.set_exp(lifetime=timedelta(days=2))
            else:
                # Set token expiration to a short duration if "Remember Me" is not checked
                refresh_token.set_exp(lifetime=timedelta(days=1))
            # Output dictionary
            user_details = {
                "refresh": str(refresh_token),
                "access": str(refresh_token.access_token),
                "user_id": str(user.id),
            }
            user_logged_in = Signal()
            user_logged_in.send(sender=user.__class__, request=request, user=user)

            return Response(user_details, status=status.HTTP_202_ACCEPTED)
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# customizing the claims in tokens generated by the TokenObtainPairView
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Adding custom claims
        token["id"] = user.id
        return token


# Token serializer
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


# User Account Logout API
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_205_RESET_CONTENT,
            )
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# User Account Forgot Password API
class ForgotPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            try:
                user = CustomUser.objects.get(email=email)

            except CustomUser.DoesNotExist:
                return Response(
                    {"message": "User with this email does not exist."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            uid = urlsafe_base64_encode(force_bytes(str(user.pk)))
            token = default_token_generator.make_token(user)

            # Calling custom email generator
            send_forget_password_mail(user, uid, token)

            return Response(
                {"message": "Password reset email has been sent."},
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# User Account Reset Password API
class ResetPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            query_dict = {**request.query_params}

            token = query_dict.get("token")[0]
            uidb64 = query_dict.get("uid")[0]

            uid = urlsafe_base64_decode(uidb64)
            user = CustomUser.objects.get(pk=uid)

        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist) as e:
            print(e)
            return Response(
                {"message": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST
            )

        if default_token_generator.check_token(user, token):
            serializer = ResetPasswordSerializer(data=request.data)
            if serializer.is_valid():
                new_password = serializer.validated_data["new_password"]
                user.set_password(new_password)
                user.save()

                return Response(
                    {"message": "Password reset successful."}, status=status.HTTP_200_OK
                )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"message": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST
        )


# USER PROFILE OPERATIONS
class UserRetrieveUpdateAPIView(RetrieveUpdateAPIView):
    # Allow only authenticated users to access this url
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomSerializer

    # View user data
    def get(self, request, id, *args, **kwargs):
        try:
            user_profile = CustomUser.objects.get(id=id)
        except CustomUser.DoesNotExist:
            return Response(
                {"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = CustomSerializer(user_profile, partial=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # Update user data
    def put(self, request, id, *args, **kwargs):
        try:
            user_data = CustomUser.objects.get(id=id)
        except CustomUser.DoesNotExist:
            return Response(
                {"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND
            )

        data = {
            "first_name": request.data.get("first_name"),
            "last_name": request.data.get("last_name"),
            "email": request.data.get("email"),
            "avatar": request.data.get("avatar"),
        }
        serializer = CustomSerializer(user_data, data=data, partial=True)
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            # Sending user profile update notification email
            send_user_profile_update_notification([user_data])

            return Response(serializer.data, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # Delete user data
    def delete(self, request, id, *args, **kwargs):
        try:
            try:
                user_data = CustomUser.objects.get(id=id)
            except CustomUser.DoesNotExist:
                return Response(
                    {"error": "User profile not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            # Send User profile delete notification email
            send_user_profile_delete_notification([user_data])
            # Delete user profile
            user_data.delete()
            return Response(
                data={"message": "User profile deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


###############################################################################################


# CRUD OPERATION FOR CLINIC
class ClinicListView(APIView):
    permission_classes = [
        permissions.AllowAny,
    ]

    def post(self, request, *args, **kwargs):
        data = {
            "clinic_name": request.data.get("clinic_name"),
            "contact_number": request.data.get("mobile_number"),
            "address": request.data.get("address"),
            "city": request.data.get("city"),
            "country": request.data.get("country"),
            "email": request.data.get("email"),
            "status": request.data.get("status"),
            "user": request.user.id,
        }

        serializer = ClinicSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        try:
            queryset = Clinic.objects.all().order_by("-created_at").values()

            # Filter by query parameters
            clinic_id = self.request.GET.get("clinic_id", None)
            clinic_name = self.request.GET.get("clinic_name", None)
            email = self.request.GET.get("email", None)
            country = self.request.GET.get("country", None)
            city = self.request.GET.get("city", None)

            if clinic_name:
                queryset = queryset.filter(clinic_name__icontains=clinic_name)
            if email:
                queryset = queryset.filter(email=email)
            if clinic_id:
                queryset = queryset.filter(clinic_id=clinic_id)
            if country:
                queryset = queryset.filter(country=country)
            if city:
                queryset = queryset.filter(city=city)

            # Applying pagination
            set_limit = self.request.GET.get("limit")
            paginator = Paginator(queryset, set_limit)
            page_number = self.request.GET.get("page")

            # Use GET instead of data to retrieve the page number
            page_obj = paginator.get_page(page_number)
            serializer = ClinicSerializer(page_obj, many=True)

            # result dictionary
            payload = {
                "Page": {
                    "totalRecords": queryset.count(),
                    "current": page_obj.number,
                    "next": page_obj.has_next(),
                    "previous": page_obj.has_previous(),
                    "totalPages": page_obj.paginator.num_pages,
                },
                "Result": serializer.data,
            }

            return Response(
                payload,
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


############################################################################################################################


# CRUD FOR CLINIC STAFF
class StaffRelationshipManagementView(APIView):
    permission_classes = [permissions.AllowAny]

    # ADD
    def post(self, request, *args, **kwargs):
        data = {
            "clinic_name": request.data.get("clinic_name"),
            "first_name": request.data.get("first_name"),
            "last_name": request.data.get("last_name"),
            "designation": request.data.get("designation"),
            "email": request.data.get("email"),
            "status": request.data.get("status"),
        }

        serializer = ClinicStaffSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # LIST VIEW
    def get(self, request, *args, **kwargs):
        try:
            queryset = ClinicMember.objects.all().order_by("-created_at")

            # Filter by query parameters
            filter_params = {
                "clinic_name": self.request.GET.get("clinic_name"),
                "first_name": self.request.GET.get("first_name"),
                "designation": self.request.GET.get("designation"),
                "email": self.request.GET.get("email"),
                "clinic_id": self.request.GET.get("clinic_id"),
                "staff_id": self.request.GET.get("staff_id"),
            }
            # Parsing key and value into conditional filter
            filters = {
                field: value
                for field, value in filter_params.items()
                if value is not None
            }

            if filters:
                queryset = queryset.filter(**filters)

            # Applying pagination
            set_limit = self.request.GET.get("limit")
            paginator = Paginator(queryset, set_limit)
            page_number = self.request.GET.get("page")
            # Use GET instead of data to retrieve the page number
            page_obj = paginator.get_page(page_number)
            serializer = ClinicStaffSerializer(page_obj, many=True)

            # result dictionary
            payload = {
                "Page": {
                    "totalRecords": queryset.count(),  # Use count() instead of len()
                    "current": page_obj.number,
                    "next": page_obj.has_next(),
                    "previous": page_obj.has_previous(),
                    "totalPages": page_obj.paginator.num_pages,
                },
                "Result": serializer.data,  # Include the serialized data
            }

            return Response(
                payload,
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # UPDATE
    def put(self, request, staff_id, *args, **kwargs):
        try:
            member_data = ClinicMember.objects.get(staff_id=staff_id)
        except ClinicMember.DoesNotExist:
            return Response(
                {"error": "Staff member not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = ClinicStaffSerializer(member_data, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # DELETE
    def delete(self, request, staff_id, *args, **kwargs):
        try:
            member_data = ClinicMember.objects.get(staff_id=staff_id)
        except ClinicMember.DoesNotExist:
            return Response(
                {"error": "Staff Member not found."}, status=status.HTTP_404_NOT_FOUND
            )
        member_data.delete()
        return Response(
            data={"message": "Staff Member data deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )


############################################################################################################################


# Add Drug
class DrugInventoryManagement(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        data = {
            "drug_name": request.data.get("drug_name"),
            "company": request.data.get("company"),
            "generic_name": request.data.get("generic_name"),
            "quantity": request.data.get("quantity"),
            "unit_price": request.data.get("unit_price"),
            "user": request.user.id,
        }

        serializer = DrugSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # View Drug information List
    def get(self, request, *args, **kwargs):
        try:
            queryset = (
                Drug.objects.filter(user=request.user.id)
                .order_by("-created_at")
                .values()
            )

            # Applying pagination
            set_limit = self.request.GET.get("limit")
            paginator = Paginator(queryset, set_limit)
            page_number = self.request.data.get("page")

            page_obj = paginator.get_page(page_number)
            serializer = DrugSerializer(page_obj.object_list, many=True)

            # result dictionary
            payload = {
                "Page": {
                    "totalRecords": queryset.count(),
                    "current": page_obj.number,
                    "next": page_obj.has_next(),
                    "previous": page_obj.has_previous(),
                    "totalPages": page_obj.paginator.num_pages,
                },
                "Result": serializer.data,
            }

            return Response(
                payload,
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # Update clinic data
    def put(self, request, token, *args, **kwargs):
        try:
            drug = Drug.objects.get(token=token)
        except Drug.DoesNotExist:
            return Response(
                {"error": "Drug not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = DrugSerializer(drug, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Delete clinic data
    def delete(self, request, token, *args, **kwargs):
        try:
            drug_data = Drug.objects.get(token=token)
        except Drug.DoesNotExist:
            return Response(
                {"error": "Drug not found."}, status=status.HTTP_404_NOT_FOUND
            )
        drug_data.delete()
        return Response(
            data={"message": "Data deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )


############################################################################################################################


class AppointmentManagement(APIView):
    permission_classes = [permissions.AllowAny]

    # Create appointment
    def post(self, request):
        # Retrieve the primary key values of the procedures
        procedure_ids = request.data.get("procedures", [])
        print(procedure_ids)

        data = {
            "clinic_name": request.data.get("clinic_name"),
            "relatedRecipient": request.data.get("relatedRecipient"),
            "patient_first_name": request.data.get("patient_first_name"),
            "patient_last_name": request.data.get("patient_last_name"),
            "gender": request.data.get("gender"),
            "contact_number": request.data.get("contact_number"),
            "email": request.data.get("email"),
            "recurring_patient": request.data.get("recurring_patient"),
            "appointment_date": request.data.get("appointment_date"),
            "appointment_slot": request.data.get("appointment_slot"),
            "status": request.data.get("status"),
            "procedures": procedure_ids,  
        }

        serializer = AppointmentSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # View appointment List
    def get(self, request, *args, **kwargs):
        try:
            queryset = PatientAppointment.objects.all().order_by("-created_at")

            # filter and Search function for list
            filter_params = {
                "appointment_id": self.request.GET.get("appointment_id"),
                "clinic_name": self.request.GET.get("clinic_name"),
                "relatedDepartment": self.request.GET.get("relatedDepartment"),
                "relatedRecipient": self.request.GET.get("relatedRecipient"),
                "patient_first_name": self.request.GET.get("patient_first_name"),
                "patient_last_name": self.request.GET.get("patient_last_name"),
                "gender": self.request.GET.get("gender"),
                "recurring_patient": self.request.GET.get("recurring_patient"),
                "procedures": self.request.GET.get("procedures"),
                "appointment_date": self.request.GET.get("appointment_date"),
                "appointment_slot": self.request.GET.get("appointment_slot"),
                "status": self.request.GET.get("status"),
            }
            # Parsing key and value into conditional filter
            filters = {
                field: value
                for field, value in filter_params.items()
                if value is not None
            }

            if filters:
                queryset = queryset.filter(**filters)

            # Applying pagination
            set_limit = self.request.GET.get("limit")
            paginator = Paginator(queryset, set_limit)
            page_number = self.request.GET.get("page")
            # Use GET instead of data to retrieve the page number
            page_obj = paginator.get_page(page_number)
            serializer = AppointmentSerializer(page_obj, many=True)

            # result dictionary
            payload = {
                "Page": {
                    "totalRecords": queryset.count(),
                    "current": page_obj.number,
                    "next": page_obj.has_next(),
                    "previous": page_obj.has_previous(),
                    "totalPages": page_obj.paginator.num_pages,
                },
                "Result": serializer.data,
            }

            return Response(
                payload,
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # Update clinic data
    def put(self, request, appointment_id, *args, **kwargs):
        try:
            queryset = PatientAppointment.objects.get(appointment_id=appointment_id)
        except PatientAppointment.DoesNotExist:
            return Response(
                {"error": "Appointment not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = AppointmentSerializer(queryset, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Delete clinic data
    def delete(self, request, appointment_id, *args, **kwargs):
        try:
            drug_data = PatientAppointment.objects.get(appointment_id=appointment_id)
        except PatientAppointment.DoesNotExist:
            return Response(
                {"error": "Drug not found."}, status=status.HTTP_404_NOT_FOUND
            )
        drug_data.delete()
        return Response(
            data={"message": "Data deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )
