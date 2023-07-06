# This retrieves a Python logging instance (or creates it)
import logging
log = logging.getLogger(__name__)

# Within the project directory
from .models import (
    CustomUser,
    Clinic,
    ClinicMember,
    PatientAppointment,
    ClientDataCollectionPool,
    PharmacyInventory,
    Prescription,
    ClientPaymentData,
)
from .serializer import (
    ClinicSerializer,
    CustomSerializer,
    ClinicStaffSerializer,
    MedicalProceduresTypes,
    AppointmentSerializer,
    ClientDataCollectionPoolSerializer,
    PharmacyInventorySerializer,
    PrescriptionSerializer,
    ClientPaymentDataSerializer,
)
from .emails import (
    send_email_notification,
    send_forget_password_mail,
    send_user_profile_update_notification,
    send_user_profile_delete_notification,
    send_email_notification_to_patient,
    send_email_notification_to_staff,
    send_pay_link_via_email,
)
from .filter import clean_data
from .sms import send_sms_notification_patient, send_sms_notification_staff_member
from .otp_maker import generate_time_based_otp, is_otp_valid
from .helper_functions import (fetch_master_data, create_payment_link, DecimalEncoder)
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
from rest_framework.decorators import api_view, renderer_classes
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken,
    BlacklistedToken,
)

# External Django libraries and modules
import json
import requests
import datetime
import stripe
# For getting the operating system name
import platform 
# For executing a shell command
import subprocess  
from decimal import Decimal
from datetime import date
from datetime import timedelta
from collections import defaultdict, Counter
from django.dispatch import Signal
from django.db.models import F
from django.views import View
from django.shortcuts import render
from django.conf import settings
from django.http import JsonResponse
from django.http import HttpResponse
from django.core.paginator import Paginator, EmptyPage
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string


#####################################################################################################################

# Check Server Status
class PingTest(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        """
        Returns True if host (str) responds to a ping request.
        Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
        """
        try:
            host = settings.YOUR_DOMAIN
            # Option for the number of packets as a function of the operating system
            param = '-c' if platform.system().lower() == 'linux' else '-n'
            # Building the command. Ex: "ping -c 1 example.com"
            command = ['ping', param, '1', host]
            # Execute the ping command and check the return status
            status = subprocess.call(command) == 0
            if status:
                return Response(data={"message": "Server is reachable"})
            else:
                return Response(data={"message": "Server is not reachable"})
        except Exception as e:
            return Response(data={"message": str(e)})


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
                log.warning("email is already in use")
                return Response(
                    data={"message": "Email already exists"},
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Password Mismatch Case
            if password != confirm_password:
                log.warning("password mismatch")
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
            # Generate and send the 6 digit OTP to the user's email address
            OTP = generate_time_based_otp()

            # Store the email and generated OTP in the session or any other storage
            request.session["email"] = email
            request.session["otp"] = OTP
            request.session["password"] = password

            # Email OTP verification
            send_email_notification([user], OTP)
            
            log.info("Session Data saved! Notification email sent to %s.", user.email)
            # Saving user information temporarily till they verify
            user.save()
            log.info("New user registered, Account activation pending.")
            return Response(
                data={
                    "message": "Your account has been registered now. To activate it, Confirm OTP."
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            log.error(str(e))
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
                OTP = generate_time_based_otp()
                # Update the OTP stored OTP in session
                request.session["otp"] = OTP
                # Resend OTP email
                send_email_notification([stored_email], OTP)
                # Increment tries and update session
                count += 1
                request.session["resend_otp_count"] = count
                
                log.info(f"{count} of 3 OTP Sent!")
                return Response(
                    data={
                        "message": f"Attempt: {count} of 3: Email with a 6-digit OTP has been sent to {stored_email}. Please check your email."
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                log.warning("Max OTP attempts exceeded")
                return Response(
                    data={
                        "message": "Maximum number of OTP resend attempts reached. Please contact support for assistance."
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)


# Email OTP Based User Account Verification
class VerifyOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            otp = serializer.validated_data["otp"]

        if is_otp_valid(otp) != True:
            log.critical("OTP validation timed out!")
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

                    log.info("Session data deleted and %s activated successfully", user.email)
                    return Response(
                        data={
                            "error_message": "Account verified successfully. You can now log in."
                        },
                        status=status.HTTP_200_OK,
                    )
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)


# User Account Login API
class LoginView(APIView):
    permission_classes = [permissions.AllowAny,]

    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get("email")
            password = request.data.get("password")
            remember_me = request.data.get("remember_me")

            # Rain check from user database
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                log.error("Login Failed! User does not exist")
                return Response(
                    {"message": "User with this email does not exist."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Authentication
            user = authenticate(request, email=email, password=password)
            # Error Case
            if user is None:
                log.error("Login Failed due to invalid input.")
                return Response(
                    data={"message": "Email or Password is incorrect"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            elif password is None:
                log.error("Login Failed due to invalid password.")
                return Response(
                    data={"message": "Enter the password to login!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Login the user
            login(request, user)

            # Generate tokens
            refresh_token = RefreshToken.for_user(user)

            if remember_me == True:
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
            log.info("User logged in successfully.")
            return Response(user_details, status=status.HTTP_202_ACCEPTED)
        except Exception as e:
            log.error(str(e))
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
            log.info("Token Blacklisted and User logged out.")
            return Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# User Account Forgot Password API
class ForgotPasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self, request, *args, **kwargs):
        serializer = ForgotPasswordSerializer(data=request.data)
        try:
            if serializer.is_valid():
                email = serializer.validated_data["email"]
                try:
                    user = CustomUser.objects.get(email=email)

                except CustomUser.DoesNotExist:
                    log.error("User does not exist")
                    return Response(
                        {"message": "User with this email does not exist."},
                        status=status.HTTP_404_NOT_FOUND,)

                uid = urlsafe_base64_encode(force_bytes(str(user.pk)))
                token = default_token_generator.make_token(user)

                # Calling custom email generator
                send_forget_password_mail(user, uid, token)
                log.info("Forgot password email sent to %s", email)
                return Response(
                    {"message": "Password reset email has been sent."},
                    status=status.HTTP_200_OK,
                )
            log.critical(str(serializer.errors))
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# User Account Reset Password API
class ResetPasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self, request, *args, **kwargs):
        try:
            token = request.query_params.get("token")
            uidb64 = request.query_params.get("uid")

            uid = urlsafe_base64_decode(uidb64)
            user = CustomUser.objects.get(pk=uid)

        except (TypeError, ValueError, OverflowError, ObjectDoesNotExist) as e:
            log.critical(str(e))
            return Response(
                {"message": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            serializer = ResetPasswordSerializer(data=request.data)
            if serializer.is_valid():
                new_password = serializer.validated_data["new_password"]
                user.set_password(new_password)
                user.save()

                log.info("Password reset successfully")
                return Response({"message": "Password reset successful."}, status=status.HTTP_200_OK)
            else:
                log.error(serializer.errors)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        log.error("Invalid reset link.")
        return Response({"message": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)


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
            log.warning("User with id %s does not exist", id)
            return Response(
                {"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = CustomSerializer(user_profile, partial=True)
        log.info("Profile generated")
        return Response(serializer.data, status=status.HTTP_200_OK)

    # Update user data
    def put(self, request, id, *args, **kwargs):
        try:
            user_data = CustomUser.objects.get(user__id=id)
        except CustomUser.DoesNotExist:
            log.warning("User with id %s does not exist", id)
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
            
            log.info("User profile updated & notification email sent to %s", data["email"])
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ValidationError as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # Delete user data
    def delete(self, request, id, *args, **kwargs):
        try:
            user_data = CustomUser.objects.get(user__id=id)
        except ObjectDoesNotExist:
            log.warning("User with id %s does not exist", id)
            return Response(
                {"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND,)

        # Send User profile delete notification email
        send_user_profile_delete_notification([user_data])

        # Delete user profile
        user_data.delete()

        log.info("User profile deleted & notification email sent to %s", user_data.email)
        return Response(
            data={"message": "User profile deleted successfully"}, status=status.HTTP_204_NO_CONTENT,)


############################################################################################################################


# CRUD OPERATION FOR CLINIC
class ClinicListView(APIView):
    permission_classes = [permissions.AllowAny]

    # ADD
    def post(self, request, *args, **kwargs):
        try:
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
                log.info("Clinic Added Successfully")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            log.critical(str(serializer.errors))
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
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
            paginated_queryset = paginator.paginate_queryset(
                queryset, request, view=self
            )
            serializer = ClinicSerializer(paginated_queryset, many=True)
            # Constructing response payload
            payload = {
                "Page": {
                    "totalRecords": paginator.get_total_items(queryset),
                    "current": paginator.get_page(request),
                    "totalPages": paginator.calculate_total_pages(
                        paginator.get_total_items(queryset),
                        paginator.get_limit(request),
                    ),
                },
                "Result": serializer.data,
            }
            log.info("Request clinic payload loaded successfully")
            return Response(payload, status=status.HTTP_200_OK)
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # DELETE
    def delete(self, request, clinic_id, *args, **kwargs):
        try:
            clinic_data = Clinic.objects.get(clinic_id=clinic_id)
        except Clinic.DoesNotExist:
            log.warning("Invalid Clinic ID provided")
            return Response({"error": "Clinic not found."}, status=status.HTTP_404_NOT_FOUND)
        
        clinic_data.delete()
        log.info("Clinic data with ID %s has been deleted", clinic_id)
        return Response({"message": "Clinic data deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


############################################################################################################################


# CRUD FOR CLINIC STAFF
class StaffRelationshipManagementView(APIView):
    permission_classes = [permissions.AllowAny]

    # ADD
    def post(self, request, *args, **kwargs):
        try:
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
                log.info("Staff member added successfully")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            log.error(serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
    # LIST VIEW
    def get(self, request, *args, **kwargs):
        try:
            queryset = ClinicMember.objects.all().order_by("-created_at")

            # Setting up filter parameters for search results
            filter_params = {
                "clinic_name": self.request.GET.get("clinic_name"),
                "staff_first_name": self.request.GET.get("staff_first_name"),
                "staff_designation": self.request.GET.get("staff_designation"),
                "staff_email": self.request.GET.get("staff_email"),
                "shift_type": self.request.GET.get("shift_type"),
                "clinic_id": self.request.GET.get("clinic_id"),
                "staff_id": self.request.GET.get("staff_id"),
            }
            
            filters = {
                field: value
                for field, value in filter_params.items()
                if value is not None
            }

            if filters:
                log.debug("Filter triggered: %s", filters)
                queryset = queryset.filter(**filters)

            # Creating a new variable "Availability" which check if staff is available
            # or not by comparing current date with appointment dates
            # All adding another variable "Appointment Count" which provides the number of appointment
            # a staff member is assigned to.
            appointment_queryset = PatientAppointment.objects.all().order_by("-created_at")
            
            unique_recipients = appointment_queryset.values_list("relatedRecipient", flat=True).distinct()

            current_date = date.today()
            recipient_dict = {}

            for recipient in unique_recipients:
                recipient_appointments = appointment_queryset.filter(relatedRecipient=recipient)
                appointment_dates = recipient_appointments.values_list("appointment_date", flat=True)
                
                # Convert the queryset values to a list of date strings
                appointment_dates = [
                    date_str.strftime("%Y-%m-%d")
                    for date_str in appointment_dates
                ]

                appointment_count = len(appointment_dates)
                availability = True

                if str(current_date) in appointment_dates:
                    availability = False

                recipient_dict[recipient] = {
                    "appointment_count": appointment_count,
                    "availability": availability,
                }
                
            # Applying pagination
            set_limit = self.request.GET.get("limit")
            paginator = Paginator(queryset, set_limit)
            page_number = self.request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            serializer = ClinicStaffSerializer(page_obj, many=True)

            result_data = serializer.data

            for item in result_data:
                recipient_id = item["staff_id"]
                if recipient_id in recipient_dict:
                    item.update(recipient_dict[recipient_id])
                else:
                    item["appointment_count"] = "N/A"
                    item["availability"] = True

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
            log.info("Staff Member data generated successfully")
            return Response(payload, status=status.HTTP_200_OK)
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # UPDATE
    def put(self, request, staff_id, *args, **kwargs):
        try:
            member_data = ClinicMember.objects.get(staff_id=staff_id)
        except ClinicMember.DoesNotExist:
            log.warning("Invalid staff ID provided")
            return Response({"error": "Staff member not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = ClinicStaffSerializer(member_data, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            log.info("Staff member ID %s has been updated", member_data.staff_id)
            return Response(serializer.data, status=status.HTTP_202_ACCEPTED)
        
        log.error(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # DELETE
    def delete(self, request, staff_id, *args, **kwargs):
        try:
            member_data = ClinicMember.objects.get(staff_id=staff_id)
        except ClinicMember.DoesNotExist:
            log.warning("Invalid staff ID provided")
            return Response({"error": "Staff Member not found."}, status=status.HTTP_404_NOT_FOUND)
        
        member_data.delete()
        log.info("Staff member ID %s has been deleted successfully", staff_id)
        return Response(
            {"message": "Staff Member data deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


############################################################################################################################


# Appointment view
class AppointmentManagement(APIView):
    permission_classes = [permissions.AllowAny]

    # Create a new Appointment
    def post(self, request):
        try:
            data = {
            "clinic_name": request.data.get("clinic_name"),
            "relatedDepartment": request.data.get("relatedDepartment"),
            "relatedRecipient": request.data.get("relatedRecipient"),
            "patient_first_name": request.data.get("patient_first_name"),
            "patient_last_name": request.data.get("patient_social_security_ID"),
            "patient_social_security_ID": request.data.get("patient_last_name"),
            "patient_gender": request.data.get("patient_gender"),
            "patient_contact_number": request.data.get("patient_contact_number"),
            "patient_email": request.data.get("patient_email"),
            "recurring_patient": request.data.get("recurring_patient"),
            "appointment_date": request.data.get("appointment_date"),
            "appointment_slot": request.data.get("appointment_slot"),
            "status": request.data.get("status"),
            "procedures": request.data.get("procedures"),}

            # Fetching data
            queryset = ClinicMember.objects.filter(staff_id=data.get("relatedRecipient")).values(
                "staff_first_name", "staff_last_name", "staff_email", "staff_contact_number"
            ).first()

            # Sending Email Notifications
            send_email_notification_to_staff(queryset)
            send_email_notification_to_patient(data, queryset)
            log.info("Appointment creation notification email sent to both client and consultant.")

            # Sending SMS Notifications
            send_sms_notification_staff_member(queryset)
            send_sms_notification_patient(data, queryset)
            log.info("Appointment creation notification SMS sent to both client and consultant.")
            
            serializer = AppointmentSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                
                log.info("Appointment with ID %s created", serializer.appointment_id)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            log.critical(str(serializer.errors))
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST,)

    # View appointment List
    def get(self, request, appointment_id=None,*args, **kwargs):
        try:
            if appointment_id is None:
                log.info("View all appointment data API triggered.")
                queryset = queryset = PatientAppointment.objects.all().order_by("-created_at")
                # filter and Search function for list
                filter_params = {
                    "appointment_id": self.request.GET.get("appointment_id"),
                    "clinic_name": self.request.GET.get("clinic_name"),
                    "relatedDepartment": self.request.GET.get("relatedDepartment"),
                    "relatedRecipient": self.request.GET.get("relatedRecipient"),
                    "patient_first_name": self.request.GET.get("patient_first_name"),
                    "patient_last_name": self.request.GET.get("patient_last_name"),
                    "patient_gender": self.request.GET.get("patient_gender"),
                    "date_of_birth": self.request.GET.get("date_of_birth"),
                    "patient_age": self.request.GET.get("patient_age"),
                    "patient_email": self.request.GET.get("patient_email"),
                    "patient_contact_number": self.request.GET.get("patient_contact_number"),
                    "procedures": self.request.GET.get("procedures"),
                    "recurring_patient": self.request.GET.get("recurring_patient"),
                    "appointment_description": self.request.GET.get("appointment_description"),
                    "appointment_date": self.request.GET.get("appointment_date"),
                    "appointment_slot": self.request.GET.get("appointment_slot"),
                    "appointment_status": self.request.GET.get("appointment_status"),
                }

                # Parsing key and value into conditional filter
                filters = {
                    field: value
                    for field, value in filter_params.items()
                    if value is not None
                }

                if filters:
                    log.debug("Filter triggered: %s", filters)
                    queryset = queryset.filter(**filters)

                # Applying pagination
                set_limit = int(self.request.GET.get("limit"))
                paginator = Paginator(queryset, set_limit)
                page_number = int(self.request.GET.get("page"))
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
                log.info("All Appointment Data fetched Successfully")
                return Response(payload, status=status.HTTP_200_OK,)
            else:
                log.info("API view triggered for AID: %s", appointment_id)
                appointment = PatientAppointment.objects.filter(appointment_id=appointment_id).order_by("-created_at").values().first()
                selected_procedures = MedicalProceduresTypes.objects.filter(patientappointment=appointment["appointment_id"]).values()
                staff = (ClinicMember.objects.filter(staff_id=str(appointment["relatedRecipient_id"])).values().first())
                clinic = (Clinic.objects.filter(clinic_id=str(staff["clinic_name_id"])).values().first())
                
                appointment_dict = {**appointment, "selected_procedures": selected_procedures, **staff, **clinic,}
                
                log.info("Custom data generated for AID: %s" % appointment_id)
                return Response({"masterData": appointment_dict}, status=status.HTTP_200_OK,)
        except Exception as e:
            log.critical(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # Update clinic data
    def put(self, request, appointment_id, *args, **kwargs):
        try:
            queryset = PatientAppointment.objects.get(appointment_id=appointment_id)
        except PatientAppointment.DoesNotExist:
            log.warning("Invalid Appointment ID provided.")
            return Response({"error": "Appointment not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = AppointmentSerializer(queryset, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            log.info("AID %s updated successfully", appointment_id)
            return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

        log.error(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    # Delete clinic data
    def delete(self, request, appointment_id, *args, **kwargs):
        try:
            drug_data = PatientAppointment.objects.get(appointment_id=appointment_id)
        except PatientAppointment.DoesNotExist:
            log.warning("Invalid appointment ID provided")
            return Response({"error": "Drug not found."}, status=status.HTTP_404_NOT_FOUND)
        drug_data.delete()
        log.info("AID %s has been deleted successfully", appointment_id)
        return Response(data={"message": "Data deleted successfully"}, status=status.HTTP_204_NO_CONTENT,)


############################################################################################################################

# Client Data
class ClientDataManagement(APIView):
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, *args, **kwargs):
        try:
            queryset = ClientDataCollectionPool.objects.all().order_by("-profile_created_at")

            # filter and Search function for list
            filter_params = {
                "client_id": self.request.GET.get("client_id"),
                "client_social_security_ID": self.request.GET.get("client_social_security_ID"),
                "client_first_name": self.request.GET.get("client_first_name"),
                "client_last_name": self.request.GET.get("client_last_name"),
                "client_dob": self.request.GET.get("client_dob"),
                "client_gender": self.request.GET.get("client_gender"),
                "client_email": self.request.GET.get("client_email"),
                "client_billing_address": self.request.GET.get("client_billing_address"),
                "appointment_count": self.request.GET.get("appointment_count"),
                "medical_procedure_history": self.request.GET.get("medical_procedure_history"),
                "prescription_count": self.request.GET.get("prescription_count"),
                "medication_history": self.request.GET.get("medication_history"),
                "transactions_made": self.request.GET.get("transactions_made"),
                "total_billings": self.request.GET.get("total_billings"),
                "profile_last_updated": self.request.GET.get("profile_last_updated"),
                "profile_created_at": self.request.GET.get("profile_created_at"),
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
            serializer = ClientDataCollectionPoolSerializer(page_obj, many=True)

            # result dictionary
            payload = {
                "Page": {
                    "totalRecords": queryset.count(),
                    "current": page_obj.number,
                    "next": page_obj.has_next(),
                    "previous": page_obj.has_previous(),
                    "totalPages": page_obj.paginator.num_pages,
                },
                "Result": serializer.data,}
            
            # Medical Procedure count based on patient consultation
            key_counts = defaultdict(int)
            for procedure in payload["Result"]:
                individual_procedures = procedure["medical_procedure_history"]
                for key in individual_procedures:
                    key_counts[key] += 1
            medProceduresCount = Counter(dict(key_counts))

            # Total prescription and appointments created for patients
            prescriptionCount = sum(int(prescription["prescription_count"]) for prescription in payload["Result"])
            appointmentCount = sum(int(appointment["appointment_count"]) for appointment in payload["Result"])
            totalBilling = sum(Decimal(revenue["total_billings"]) for revenue in payload["Result"])
            averageBilling = totalBilling / Decimal(len(payload["Result"]))

            # Adding a nest in the dictionary for respective variable
            payload["Dashboard_stats"] = {
                "total_medical_procedure_count": medProceduresCount,
                "total_prescriptions_created": prescriptionCount,
                "total_appointment_handled": appointmentCount,
                "total_revenue_generated": totalBilling,
                "average_patient_treatment_cost": averageBilling
            }
            log.info("Client data generated")
            return Response(payload, status=status.HTTP_200_OK,)
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


############################################################################################################################


class PharmacyInventoryManagement(APIView):
    permission_classes = [permissions.AllowAny]

    # ADD DRUG
    def post(self, request):
        try:
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
                log.info("New Drug %s added successfully", serializer.drug_id)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            log.critical(serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST,)
        
    # View Drug List
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
            log.info("Drug data generated")
            return Response(payload, status=status.HTTP_200_OK,)

        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


############################################################################################################################

# Prescription Creation View

class PrescriptionManagement(APIView):
    permission_classes = [permissions.AllowAny]

    # Add Prescription
    def post(self, request):
        data = {
            "clinic_name": request.data.get("clinic_name"),
            "consultant": request.data.get("consultant"),
            "appointment_id": request.data.get("appointment_id"),
            "medications_json": request.data.get("medications_json"),
            "coupon_discount": request.data.get("coupon_discount"),
            "description": request.data.get("description")}
        
        print(type(data['medications_json']))
        updated_medications_json = []
        try:
            log.debug("Medications data fetching")
            for med in data.get("medications_json", []):
                quantity = med.get('quantity')
                drug_id = med.get('drug_id')
                dosage_freq = med.get('dosage_freq')
                verified_data = PharmacyInventory.objects.get(drug_id=drug_id)
                medication = {
                    "medicine_id": verified_data.drug_id,
                    "medicine_name": verified_data.drug_name,
                    "purpose": verified_data.drug_class,
                    "quantity": quantity,
                    "amount_per_unit": verified_data.price,
                    "total_payable_amount": Decimal(int(verified_data.price) * int(quantity)),
                    "stripe_price_id": verified_data.stripe_price_id,
                    "dosage_freq": dosage_freq
                }
                updated_medications_json.append(medication)

        except PharmacyInventory.DoesNotExist as p:
            log.warning("Invalid Drug ID provided")
            return Response({"error": "PharmacyInventory with drug_id {} does not exist.".format(drug_id)}, 
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.critical(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        # Converting nested list to valid json format
        data["medications_json"] = json.dumps(updated_medications_json, cls=DecimalEncoder)

        # Finally validating through serializer
        serializer = PrescriptionSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            log.info("New PID %s created successfully", serializer.data["prescription_id"])
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        log.error(serializer.errors)
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
                "payment_status": self.request.GET.get("payment_status"),
                "created_at": self.request.GET.get("created_at"),
            }

            # Parsing key and value into conditional filter
            filters = {
                field: value for field, value in filter_params.items() if value is not None}

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
            log.info("Prescription data generated")
            return Response(payload, status=status.HTTP_200_OK,)

        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


############################################################################################################################

# View request to retrieve and share prescription related data
# to frontend to generate Prescription Report

class FetchPrescriptReceipt(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, appointment_id, prescription_id, *args, **kwargs):
        
        # Checking parameter type
        if appointment_id == 'None':
            log.debug("API with PID Triggered")
            appointment_id = None
        if prescription_id == 'None':
            log.debug("API with AID Triggered")
            prescription_id = None
        elif appointment_id is None and prescription_id is None:
            log.warning("API with no arguments passed.")
            raise ValueError("At least one of 'appointment_id' or 'prescription_id' must be provided.")
        elif appointment_id is not None and prescription_id is not None:
            log.warning("API with both arguments passed.")
            raise ValueError("This url only supports one parameter with a non-null value.")
        
        # Now fetch the data according to the parameter value
        try:
            collected_data = fetch_master_data(appointment_id=appointment_id, prescription_id=prescription_id)
            log.info(f"Custom data generated using {appointment_id} and {prescription_id}")
            return Response(
                data={"masterData": collected_data}, status=status.HTTP_200_OK)
        except Exception as e:
            log.error(str(e))
            return HttpResponse(f"Error occurred: {str(e)}", status=500)


# Injecting Stripe secrete details to frontend
@csrf_exempt
def stripe_config(request):
    if request.method == 'GET':
        stripe_config = {'publicKey': settings.STRIPE_PUBLIC_KEY}
        log.warning("Stripe Public Key triggered in frontend")
        return JsonResponse(stripe_config, safe=False)


# Stripe Payment API
class PrescriptionPaymentCheckoutSessionView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, prescription_id, *args, **kwargs):
        try:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            # Fetching the data related to the unique prescription_id
            prescription_dict = fetch_master_data(appointment_id=None, prescription_id=prescription_id)
            log.info("Custom Data with PID %s generated", prescription_id)

            # Generating the line items for the checkout session
            items = create_payment_link(prescription_dict, return_items="line_items")
            log.info("Line items gathered")
            
            # Creating a checkout session with Stripe
            checkout_session = stripe.checkout.Session.create(
                success_url=settings.YOUR_DOMAIN + "/payment/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=settings.YOUR_DOMAIN + "/payment/cancel",
                payment_method_types=["card"],
                mode="payment",
                line_items=items,
                client_reference_id=prescription_id,
                billing_address_collection = "required")
            
            log.info("Checkout session created successfully")
            # Generating the payment link from stripe
            payment_url = checkout_session.url

            if payment_url is None:
                log.critical("Failed to create payment link")
                # Handle the error condition, such as returning an error response
                return Response(
                    data={"error": "Failed to create payment link"}, status=status.HTTP_400_BAD_REQUEST,)
                            
            # Sending the payment link to client via email
            send_pay_link_via_email(prescription_dict, payment_url)
            log.info("Payment link shared to client via email")
        
            return JsonResponse({"sessionId": checkout_session.id})
        except Exception as e:
            log.error(str(e))
            return Response(data={"Internal error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# Success View
class SuccessPaymentView(View):
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        session_id = request.GET.get('session_id')
        log.debug("Payment Session initiated")
        try:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            session_data = stripe.checkout.Session.retrieve(session_id)

            # Cleaning the fetched session data
            cleaned_data = clean_data(session_data)
            context = {'retrieve_session_data': cleaned_data}

            html_content = render_to_string('Success.html', context)

            # getting prescription id
            prescription_id = str(cleaned_data["client_reference_id"])

            # Updating payment data in ClientPaymentData Model
            payment_data = {
                'prescription_id': prescription_id,
                'session_id': cleaned_data["id"],
                'payment_intent': cleaned_data["payment_intent"],
                'payment_method': cleaned_data["payment_method_types"][0],
                'client_billing_address': cleaned_data["billing_address_collection"],
                'stripe_session_status': cleaned_data["status"],
                'stripe_payment_status': cleaned_data["payment_status"],
                'session_created_on': datetime.datetime.fromtimestamp(cleaned_data["created"]).strftime("%d-%m-%Y %H:%M:%S"),
                'session_expired_on': datetime.datetime.fromtimestamp(cleaned_data["expires_at"]).strftime("%d-%m-%Y %H:%M:%S"),}

            serializer = ClientPaymentDataSerializer(data=payment_data)
            if serializer.is_valid():
                serializer.save()
                log.info("Payment data saved")

            # Updating the payment status in prescription model
            related_prescription = Prescription.objects.get(prescription_id=prescription_id)
            prescription_data = {"payment_status": str(cleaned_data["payment_status"]).upper(),}
            
            serializer = PrescriptionSerializer(related_prescription, data=prescription_data, partial=True)
            if serializer.is_valid():
                serializer.save()
                log.info("Prescription data saved")
                
            # When Payment has been successful send client a email notification for successful payment
            # and Product allotment
            
            
            
            log.info("Payment was successful, Session expired now")
            return HttpResponse(html_content, status=status.HTTP_200_OK)
        except stripe.error.StripeError as e:
            error_message = "A payment error occurred: {}".format(e.user_message)
            log.critical(error_message)
            return JsonResponse({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.critical(str(e))
            return JsonResponse({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        
# Cancel Response View
class CancelPaymentView(View):
    def get(self, request):
        html_content = render_to_string('Cancel.html')
        return HttpResponse(html_content)
