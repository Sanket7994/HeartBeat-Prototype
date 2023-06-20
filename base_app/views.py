# Within the project directory
from .models import (
    CustomUser,
    Clinic,
    ClinicMember,
    PatientAppointment,
    PharmacyInventory,
    Prescription,
    PrescribedMedication,
)
from .serializer import (
    ClinicSerializer,
    CustomSerializer,
    ClinicStaffSerializer,
    MedicalProceduresTypes,
    AppointmentSerializer,
    PharmacyInventorySerializer,
    PrescriptionSerializer,
    PrescribedMedicationSerializer,
)
from .emails import (
    send_email_notification,
    send_forget_password_mail,
    send_user_profile_update_notification,
    send_user_profile_delete_notification,
    send_email_notification_to_patient,
    send_email_notification_to_staff,
)
from .sms import send_sms_notification_patient, send_sms_notification_staff_member
from .otp_maker import generate_time_based_otp, is_otp_valid
from .serializer import (
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    VerifyOTPSerializer,
)
from .paginator import CustomPagination

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
from datetime import date
from datetime import timedelta
from django.dispatch import Signal
from django.core.paginator import Paginator, EmptyPage
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
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
            confirm_password = request.data.get("confirm_password")
            select_role = request.data.get("select_role")

            is_email_exits = CustomUser.objects.filter(email=email)

            # Error case handling for User
            if is_email_exits.exists():
                return Response(
                    data={"message": "Email already exists"},
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Password Mismatch Case
            if password != confirm_password:
                return Response(
                    data={"message": "Passwords don't match"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # User Role selection
            if select_role == "OPERATOR":
                is_operator = True
                is_clinic_management = False
                is_active = False
            elif select_role == "CLINIC_MANAGEMENT":
                is_operator = False
                is_clinic_management = True
                is_active = False
            else:
                return Response(status=status.HTTP_400_BAD_REQUEST)

            user = CustomUser(
                email=email,
                first_name=first_name,
                last_name=last_name,
                select_role=select_role,
                is_operator=is_operator,
                is_clinic_management=is_clinic_management,
                is_active=is_active,
            )
            user.save()

            # Generate and send the 6 digit OTP to the user's email address
            OTP = generate_time_based_otp()

            # Store the email and generated OTP in the session or any other storage
            request.session["email"] = email
            request.session["otp"] = OTP
            request.session["password"] = password

            # Email OTP verification
            send_email_notification([user], OTP)

            return Response(
                data={
                    "message": "Your account has been registered now. To activate it, Confirm OTP."
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# Resend Email OTP as per user request
class ResendOTP(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            max_attempt = 3
            count = request.session.get("resend_otp_count", 0)
            if count < max_attempt:
                # Retrieve the email and OTP from the session or any other storage
                stored_email = request.session.get("email")
                # Generate new OTP
                OTP_length = 8
                OTP = generate_time_based_otp(OTP_length)
                # Resend OTP email
                send_email_notification([stored_email], OTP)
                # Increment tries and update session
                count += 1
                request.session["resend_otp_count"] = count

                return Response(
                    data={
                        "message": f"Attempt: {count} of 3: Email with a 6-digit OTP has been sent to {stored_email}. Please check your email."
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    data={
                        "message": "Maximum number of OTP resend attempts reached. Please contact support for assistance."
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)


# Email OTP Based User Account Verification
class VerifyOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            otp = serializer.validated_data["otp"]

        if is_otp_valid(otp) != True:
            return Response(
                data={
                    "error_message": "OTP Expired. Try Again as It`s only valid for 10 mins!"
                },
                status=status.HTTP_200_OK,
            )

        # Retrieve the email and OTP from the session or any other storage
        stored_email = request.session.get("email")
        stored_otp = request.session.get("otp")
        stored_password = request.session.get("password")
        try:
            if stored_email and stored_otp:
                if otp == stored_otp:
                    # OTP is valid, create the user account
                    user = CustomUser.objects.get(email=stored_email)
                    user.set_password(stored_password)
                    user.is_active = True
                    user.save()

                    # Clear the email and OTP from the session or any other storage
                    del request.session["email"]
                    del request.session["otp"]

                    return Response(
                        data={
                            "error_message": "Account verified successfully. You can now log in."
                        },
                        status=status.HTTP_200_OK,
                    )
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)


# User Account Login API
class LoginView(APIView):
    permission_classes = [
        permissions.AllowAny,
    ]

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
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# User Account Forgot Password API
class ForgotPasswordView(APIView):
    permission_classes = [
        permissions.IsAuthenticated,
    ]

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
    permission_classes = [
        permissions.IsAuthenticated,
    ]

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
    # Allow only authenticated users to access this URL
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomSerializer

    # View user data
    def get(self, request, id, *args, **kwargs):
        try:
            user_profile = CustomUser.objects.get(user__id=id)
        except CustomUser.DoesNotExist:
            return Response(
                {"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = CustomSerializer(user_profile, partial=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # Update user data
    def put(self, request, id, *args, **kwargs):
        try:
            user_data = CustomUser.objects.get(user__id=id)
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
                user_data = CustomUser.objects.get(user__id=id)
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


############################################################################################################################

# CRUD OPERATION FOR CLINIC
class ClinicListView(APIView):
    permission_classes = [permissions.AllowAny]

    # ADD
    def post(self, request, *args, **kwargs):
        data = {
            "clinic_name": request.data.get("clinic_name"),
            "clinic_address": request.data.get("clinic_address"),
            "clinic_city": request.data.get("clinic_city"),
            "clinic_zipcode": request.data.get("clinic_zipcode"),
            "clinic_country": request.data.get("clinic_country"),
            "clinic_logo": request.data.get("clinic_logo"),
            "clinic_contact_number": request.data.get("clinic_contact_number"),
            "clinic_email": request.data.get("clinic_email"),
            "clinic_status": request.data.get("clinic_status"),
            "user": request.user.id,
        }

        serializer = ClinicSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # VIEW
    def get(self, request, *args, **kwargs):
        try:
            queryset = Clinic.objects.all().order_by("-created_at")

            # Filter by query parameters
            clinic_id = self.request.GET.get("clinic_id")
            clinic_name = self.request.GET.get("clinic_name")
            email = self.request.GET.get("clinic_email")
            country = self.request.GET.get("clinic_country")
            city = self.request.GET.get("clinic_city")

            if clinic_name:
                queryset = queryset.filter(clinic_name__icontains=clinic_name)
            if email:
                queryset = queryset.filter(clinic_email=email)
            if clinic_id:
                queryset = queryset.filter(id=clinic_id)
            if country:
                queryset = queryset.filter(clinic_country=country)
            if city:
                queryset = queryset.filter(clinic_city=city)

            # Applying Pagination
            paginator = CustomPagination()
            paginated_queryset = paginator.paginate_queryset(queryset, request, view=self)
            serializer = ClinicSerializer(paginated_queryset, many=True)
            # Constructing response payload
            payload = {
                "Page": {
                    "totalRecords": paginator.get_total_items(queryset),
                    "current": paginator.get_page(request),
                    "totalPages": paginator.calculate_total_pages(paginator.get_total_items(queryset), paginator.get_limit(request)),
                },
                "Result": serializer.data,
            }

            return Response(payload, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # DELETE
    def delete(self, request, clinic_id, *args, **kwargs):
        try:
            member_data = Clinic.objects.get(clinic_id=clinic_id)
        except Clinic.DoesNotExist:
            return Response(
                {"error": "Clinic not found."}, status=status.HTTP_404_NOT_FOUND
            )
        member_data.delete()
        return Response(
            data={"message": "Clinic data deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )


############################################################################################################################


# CRUD FOR CLINIC STAFF
class StaffRelationshipManagementView(APIView):
    permission_classes = [permissions.AllowAny]

    # ADD
    def post(self, request, *args, **kwargs):
        data = {
            "clinic_name": request.data.get("clinic_name"),
            "staff_first_name": request.data.get("staff_first_name"),
            "staff_last_name": request.data.get("staff_last_name"),
            "staff_designation": request.data.get("staff_designation"),
            "shift_type": request.data.get("shift_type"),
            "staff_email": request.data.get("staff_email"),
            "staff_contact_number": request.data.get("staff_contact_number"),
            "staff_status": request.data.get("staff_status"),
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
                "staff_first_name": self.request.GET.get("staff_first_name"),
                "staff_designation": self.request.GET.get("staff_designation"),
                "staff_email": self.request.GET.get("staff_email"),
                "shift_type": self.request.GET.get("shift_type"),
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

            ##################### GETTING APPOINTMENT RELATED DATA ########################

            appointment_queryset = PatientAppointment.objects.all().order_by(
                "-created_at"
            )
            # Get all unique relatedRecipients
            unique_recipients = appointment_queryset.values_list(
                "relatedRecipient", flat=True
            ).distinct()

            current_date = date.today()
            recipient_dict = {}

            for recipient in unique_recipients:
                # Filter appointments for the current recipient
                recipient_appointments = appointment_queryset.filter(
                    relatedRecipient=recipient
                )

                # Get a list of appointment dates for the current recipient
                appointment_dates = recipient_appointments.values_list(
                    "appointment_date", flat=True
                )

                # Convert the queryset values to a list
                appointment_dates = list(appointment_dates)

                # Check if appointment_dates is empty after filtering
                if not appointment_dates:
                    appointment_count = 0
                    availability = True
                else:
                    # Get the total number of appointment dates for the current recipient
                    appointment_count = len(appointment_dates)
                    # Check availability based on the current date
                    availability = current_date not in appointment_dates

                # Assign the count and availability to the recipient key in the dictionary
                recipient_dict[recipient] = {
                    "appointment_count": appointment_count,
                    "availability": availability,
                }

            ################ Applying pagination ################

            set_limit = self.request.GET.get("limit")
            paginator = Paginator(queryset, set_limit)
            page_number = self.request.GET.get("page")
            # Use GET instead of data to retrieve the page number
            page_obj = paginator.get_page(page_number)
            serializer = ClinicStaffSerializer(page_obj, many=True)

            # result list
            result_data = serializer.data

            # Merge recipient_dict with Result by matching recipient ID
            for item in result_data:
                recipient_id = item["staff_id"]
                if recipient_id in recipient_dict:
                    item.update(recipient_dict[recipient_id])

            # result dictionary
            payload = {
                "Page": {
                    "totalRecords": queryset.count(),
                    "current": page_obj.number,
                    "next": page_obj.has_next(),
                    "previous": page_obj.has_previous(),
                    "totalPages": page_obj.paginator.num_pages,
                },
                "Result": result_data,
            }
            return Response(payload, status=status.HTTP_200_OK)
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


# Appointment view
class AppointmentManagement(APIView):
    permission_classes = [permissions.AllowAny]

    # Create appointment
    def post(self, request):
        data = {
            "clinic_name": request.data.get("clinic_name"),
            "relatedDepartment": request.data.get("relatedDepartment"),
            "relatedRecipient": request.data.get("relatedRecipient"),
            "patient_first_name": request.data.get("patient_first_name"),
            "patient_last_name": request.data.get("patient_last_name"),
            "patient_gender": request.data.get("patient_gender"),
            "patient_contact_number": request.data.get("patient_contact_number"),
            "patient_email": request.data.get("patient_email"),
            "recurring_patient": request.data.get("recurring_patient"),
            "appointment_date": request.data.get("appointment_date"),
            "appointment_slot": request.data.get("appointment_slot"),
            "status": request.data.get("status"),
            "procedures": request.data.get("procedures"),
        }

        # Fetching data
        queryset = ClinicMember.objects.filter(
            staff_id=data.get("relatedRecipient")
        ).values("staff_first_name", "staff_last_name", "staff_email", "staff_contact_number")[0]

        # Sending Email Notifications
        send_email_notification_to_staff(queryset)
        send_email_notification_to_patient(data, queryset)

        # Sending SMS Notifications
        send_sms_notification_staff_member(queryset)
        send_sms_notification_patient(data, queryset)

        serializer = AppointmentSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # View appointment List
    def get(self, request, *args, **kwargs):
        try:
            # user = request.user
            # queryset = PatientAppointment.objects.filter(user=user).order_by("-created_at")
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
                "appointment_date": self.request.GET.get("appointment_date"),
                "appointment_slot": self.request.GET.get("appointment_slot"),
                "status": self.request.GET.get("status"),
                "procedures": self.request.GET.get("procedures"),
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


############################################################################################################################


class PharmacyInventoryManagement(APIView):
    permission_classes = [permissions.AllowAny]

    # ADD DRUG
    def post(self, request):
        data = {
            "drug_name": request.data.get("drug_name"),
            "generic_name": request.data.get("generic_name"),
            "brand_name": request.data.get("brand_name"),
            "drug_class": request.data.get("drug_class"),
            "dosage_form": request.data.get("dosage_form"),
            "unit_price": request.data.get("unit_price"),
            "quantity": request.data.get("quantity"),
            "manufacture_date": request.data.get("manufacture_date"),
            "lifetime_in_months": request.data.get("lifetime_in_months"),
            "expiry_date": request.data.get("expiry_date"),
        }

        serializer = PharmacyInventorySerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # View appointment List
    def get(self, request, *args, **kwargs):
        try:
            queryset = PharmacyInventory.objects.all().order_by("-added_at")

            # filter and Search function for list
            filter_params = {
                "drug_id": self.request.GET.get("drug_id"),
                "drug_name": self.request.GET.get("drug_name"),
                "generic_name": self.request.GET.get("generic_name"),
                "brand_name": self.request.GET.get("brand_name"),
                "drug_class": self.request.GET.get("drug_class"),
                "dosage_form": self.request.GET.get("dosage_form"),
                "unit_price": self.request.GET.get("unit_price"),
                "quantity": self.request.GET.get("quantity"),
                "manufacture_date": self.request.GET.get("manufacture_date"),
                "lifetime_in_months": self.request.GET.get("lifetime_in_months"),
                "expiry_date": self.request.GET.get("expiry_date"),
                "added_at": self.request.GET.get("added_at"),
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
            serializer = PharmacyInventorySerializer(page_obj, many=True)

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

# Prescription Creation View
class PrescriptionManagement(APIView):
    permission_classes = [permissions.AllowAny]

    # Create a new Prescription
    def post(self, request):
        data = {
            "clinic_name": request.data.get("clinic_name"),
            "consultant": request.data.get("consultant"),
            "appointment_id": request.data.get("appointment_id"),
            "medications": request.data.get("medication"),
            "med_bill_amount": request.data.get("med_bill_amount"),
            "grand_total": request.data.get("grand_total"),
            "description": request.data.get("description"),
        }

        serializer = PrescriptionSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # View Prescription
    def get(self, request, *args, **kwargs):
        try:
            queryset = Prescription.objects.all().order_by("-created_at")

            # filter and Search function for list
            filter_params = {
                "prescription_id": self.request.GET.get("prescription_id"),
                "clinic_name": self.request.GET.get("clinic_name"),
                "consultant": self.request.GET.get("consultant"),
                "appointment_id": self.request.GET.get("appointment_id"),
                "medications": self.request.GET.get("medication"),
                "med_bill_amount": self.request.GET.get("med_bill_amount"),
                "grand_total": self.request.GET.get("grand_total"),
                "description": self.request.GET.get("description"),
                "created_at": self.request.GET.get("created_at"),
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
            serializer = PrescriptionSerializer(page_obj, many=True)

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


# View alloted medication in all prescriptions
class PrescribedMedicationHistory(APIView):
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, prescription_id, *args, **kwargs):
        try:
            queryset = PrescribedMedication.objects.filter(for_prescription_id=prescription_id)

            # Applying pagination
            set_limit = self.request.GET.get("limit")
            paginator = Paginator(queryset, set_limit)
            page_number = self.request.GET.get("page")
            # Use GET instead of data to retrieve the page number
            page_obj = paginator.get_page(page_number)
            serializer = PrescribedMedicationSerializer(page_obj, many=True)

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

# To dynamically update prescription receipt data to frontend

class PrescriptionInvoiceView(APIView):
    permission_classes = [permissions.AllowAny]

    # Fetch data for prescription
    def get(self, request, prescription_id, *args, **kwargs):
        try:
            prescription = Prescription.objects.filter(prescription_id=prescription_id).values().first()
            prescribed_meds = PrescribedMedication.objects.filter(for_prescription_id=prescription_id).values()
            appointment = PatientAppointment.objects.filter(appointment_id=prescription['appointment_id_id']).values().first()
            selected_procedures = MedicalProceduresTypes.objects.filter(patientappointment=appointment['appointment_id']).values()
            staff = ClinicMember.objects.filter(staff_id=str(appointment['relatedRecipient_id'])).values().first()
            clinic = Clinic.objects.filter(clinic_id=str(staff['clinic_name_id'])).values().first()

            # Convert prescribed_meds QuerySet to a list of dictionaries
            prescribed_meds_list = list(prescribed_meds)
            selected_procedures_list = list(selected_procedures)

            # Merge all the dictionaries
            prescription_dict = {
                **prescription,
                'prescribed_meds': prescribed_meds_list,
                **appointment,
                'selected_procedures': selected_procedures_list,
                **staff,
                **clinic,
            }
            return Response({"masterData": prescription_dict}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)



############################################################################################################################

