# This retrieves a Python logging instance (or creates it)
import logging
log = logging.getLogger(__name__)

# Within the project directory
from .models import *
from .emails import *
from .sms import *
from .filter import *
from .otp_maker import *
from .helper_functions import (clean_payment_data, apply_pagination, days_diff, 
                               create_payment_link, dict_to_csv, fetch_master_data,
                               get_or_create_stripe_customer, fetch_data_and_render_template)
from .helper_functions import (DecimalEncoder, DatetimeEncoder, convert_string_date_django_datetime_format)
from .serializer import *
from .seller_SETTINGS import *
from .med_seller import *
from .paginator import CustomPagination

# External REST libraries and models
import time
from rest_framework import status
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

# External Django libraries and modules

import json
import base64
import requests
import stripe
# For getting the operating system name
import platform 
# For executing a shell command
import subprocess  
from faker import Faker
from decimal import Decimal, DivisionUndefined
from django.http import FileResponse
from datetime import date, timedelta, datetime
from django.core.exceptions import ObjectDoesNotExist
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from collections import defaultdict, Counter
from django.dispatch import Signal
from django.db.models import F
from django.db.models import Q
from django.views import View
from django.db import transaction
from django.conf import settings
from django.http import JsonResponse
from django.http import HttpResponse
from django.core.cache import cache 
from django.core.paginator import Paginator
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
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
            if select_role == "SUPER_ADMIN":
                is_super_admin = True
                is_clinic_management = False
                is_active = False
            elif select_role == "CLINIC_MANAGEMENT":
                is_super_admin = False
                is_clinic_management = True
                is_active = False
            else:
                return Response(status=status.HTTP_400_BAD_REQUEST)

            user = CustomUser(
                email=email,
                first_name=first_name,
                last_name=last_name,
                select_role=select_role,
                is_super_admin=is_super_admin,
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
            return Response(data={
                "message": "Your account has been registered now. To activate it, Confirm OTP."},
                            status=status.HTTP_200_OK,)
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
                    # Clear the email a
                    # nd OTP from the session or any other storage
                    del request.session["email"]
                    del request.session["otp"]
                    log.info("Session data deleted and %s activated successfully", user.email)
                    return Response(
                        data={"error_message": "Account verified successfully. You can now log in."},
                        status=status.HTTP_200_OK,)
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


# Auto refresh access tokens If user is logged in
class TokenRefreshView(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        user = request.user
        # Check if the user is logged in
        if user.is_authenticated:
            access_token = request.auth
            if access_token:
                print(access_token.get('exp'))
                # Get the remaining time until the access token expires
                remaining_time = access_token.get('exp') - datetime.utcnow().timestamp()

                # Set the threshold time for refreshing the token
                refresh_threshold = 60 #1 minute

                if remaining_time < refresh_threshold:
                    # If the access token is about to expire, generate a new one
                    refresh = RefreshToken(access_token)
                    new_access_token = str(refresh.access_token)
                    # Return the new access token in the response
                    return Response({"access_token": new_access_token}, status=status.HTTP_200_OK)
        # Return a 401 Unauthorized status if the user is not logged in or the token doesn't require refreshing
        return Response({"detail": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)


# User Account Logout API
# Known Issue: 
# So basically every time the server was reloading because the SECRET_KEY had a new value, 
# the value of the SIGNING_KEY changed. Hence, the old refresh token became invalid, 
# even when it did not expire, as its SIGNING_KEY value was not matching with current one.
class LogoutView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                raise ValueError("Refresh token not provided in the request data.")
            if RefreshToken(refresh_token).is_expired:
                RefreshToken(refresh_token).blacklist()
                raise ValueError("Refresh token has expired.")
            RefreshToken(refresh_token).blacklist()
            log.info("Token Blacklisted and User logged out.")
            return Response(
                {"message": "Logged out successfully"}, status=status.HTTP_200_OK,)
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# User Account Forgot Password API
class ForgotPasswordView(APIView):
    permission_classes = [permissions.AllowAny,]

    def post(self, request, *args, **kwargs):
        serializer = ForgotPasswordSerializer(data=request.data)
        try:
            if serializer.is_valid():
                email = serializer.validated_data["email"]
                try:
                    user = CustomUser.objects.filter(email=email).first() 
                    
                except CustomUser.DoesNotExist:
                    log.error("User does not exist")
                    return Response(
                        {"message": "User with this email does not exist."},
                        status=status.HTTP_404_NOT_FOUND,)

                uid = urlsafe_base64_encode(force_bytes(str(user.pk)))
                print(str(user.pk))
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
    permission_classes = [permissions.AllowAny,]

    def post(self, request, *args, **kwargs):
        try:
            token = request.query_params.get("token")
            uidb64 = request.query_params.get("uid")

            # Add padding characters to uidb64
            padding = len(uidb64) % 4
            if padding:
                uidb64 += "=" * (4 - padding)

            uid = base64.urlsafe_b64decode(uidb64).decode('utf-8')
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
            user_profile = CustomUser.objects.get(id=id)
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
    permission_classes = [permissions.IsAuthenticated]

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

# To-do list or a Task Assigner for Clinic Members

class TaskManager(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self, task_id):
        try:
            return TaskAssignmentManager.objects.get(task_id=task_id)
        except TaskAssignmentManager.DoesNotExist:
            return None
    
    # CREATE ASSIGNMENT
    def post(self, request, *args, **kwargs):
        assignor_value = request.data.get("assignor")
        if assignor_value and assignor_value.startswith("SA-"):
            try:
                # Making task structure
                sub_tasks = []
                for task in request.data.get("sub_tasks"):
                    sub_tasks.append({"task": task, "status": "Pending"})
                    
                task_thread = [{"log": "A new assignment has been created", 
                               "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 
                               "user_id": assignor_value}]
                    
                data = {"task_title": request.data.get("task_title"),
                        "assignor": assignor_value,
                        "set_deadline": request.data.get("set_deadline"),
                        "department": request.data.get("department"),
                        "assignee": request.data.get("assignee"),
                        "add_collaborators": json.dumps(request.data.get("add_collaborators")),
                        "sub_tasks": json.dumps(sub_tasks, cls=DatetimeEncoder),
                        "task_thread": json.dumps(task_thread, cls=DatetimeEncoder),
                        "priority": request.data.get("priority"),
                        "task_status": request.data.get("task_status"),}
                
                serializer = TaskAssignmentManagerSerializer(data=data)
                if serializer.is_valid():
                    serializer.save()
                    log.info("Task created successfully")
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
            
                log.error(serializer.errors)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                log.error(str(e))
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        log.critical("User is not SuperAdmin")
        return Response({"error": "Only SuperAdmin is allowed to create/delete Task"}, status=status.HTTP_400_BAD_REQUEST)
    
    # VIEW ASSIGNMENT
    def get(self, request, task_id=None, staff_id=None, *args, **kwargs):
        try:
            if staff_id == 'None' and task_id == 'None':
                staff_id = None
                task_id = None
            queryset = TaskAssignmentManager.objects.all().order_by("-created_at")
            
            if staff_id is not None and task_id == 'None':
                queryset = queryset.filter(assignee=staff_id).order_by("-created_at")
                log.info("Assignment data for staff ID#%s fetched successfully", staff_id)
                payload = apply_pagination(self, request, Paginator, queryset, TaskAssignmentManagerSerializer)
                return Response(payload, status=status.HTTP_200_OK)
            
            if task_id is not None and staff_id == 'None':
                queryset = TaskAssignmentManager.objects.filter(task_id=task_id).order_by("-created_at")
                serializer = TaskAssignmentManagerSerializer(queryset, many=True)
                log.info("Assignment ID#%s fetched successfully", task_id)
                return Response(serializer.data, status=status.HTTP_200_OK)

            # Filter and search function for list
            filter_params = {
                "task_id": self.request.GET.get("task_id"),
                "created_at": self.request.GET.get("created_at"),
                "status": self.request.GET.get("status"),
            }

            # Remove None values from filter_params
            filters = {field: value for field, value in filter_params.items() if value is not None}

            if filters:
                queryset = queryset.filter(**filters)
                
            # applying pagination
            payload = apply_pagination(self, request, Paginator, queryset, TaskAssignmentManagerSerializer)

            return Response(payload, status=status.HTTP_200_OK)
        except TaskAssignmentManager.DoesNotExist:
            return Response(data={"error": "Batch Purchase Order not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # UPDATE TASK
    def put(self, request, task_id, *args, **kwargs):
        try:
            queryset = self.get_object(task_id)
            if not queryset:
                return Response({"error": "Assignment not found."}, status=status.HTTP_404_NOT_FOUND)

            fetched_data = request.data
            
            # Updating threads If they are not null
            if fetched_data["task_thread"] is not None:
                fetched_thread = json.loads(fetched_data["task_thread"])
                for thread in fetched_thread:
                    # Updating Threads
                    loaded_meta_thread = json.loads(queryset.task_thread)
                    loaded_meta_thread.append(thread)
                    update_threads = json.dumps(loaded_meta_thread)

            # Count completed tasks
            completed_task_count = sum(task["status"] == "Completed" for task in fetched_data["sub_tasks"])

            # Determine updated task status
            if completed_task_count == len(fetched_data["sub_tasks"]):
                updated_task_status = "COMPLETED"
            elif datetime.strptime(str(queryset.set_deadline), "%Y-%m-%d") < datetime.now():
                updated_task_status = "OVERDUE"
            else:
                updated_task_status = "PENDING"

            payload = {
                "sub_tasks": json.dumps(fetched_data["sub_tasks"]),
                "task_thread": update_threads,
                "task_status": updated_task_status,
            }

            # Checking nominee limit and validating changes
            if len(fetched_data["add_collaborators"]) > 0:
                colab_data = fetched_data["add_collaborators"]
                if len(colab_data["nominee"]) > 2 or len(colab_data["nominee"]) == 0:
                    colab_data = {}
                    payload["add_collaborators"] = json.dumps(colab_data)
                else:
                    # Checking if newly added members already exist in colab data
                    loaded_meta_colab_data = json.loads(queryset.add_collaborators)
                    if len(loaded_meta_colab_data) > 0:
                        similarity = sum(member in loaded_meta_colab_data["nominee"] for member in colab_data["nominee"])

                        # If NO then update the data else skip as they are already collaborators
                        if similarity != 2:
                            payload["add_collaborators"] = json.dumps(colab_data)

                        # User changed authorization and transferred full ownership
                        if colab_data["auth_type"] == "Yes":
                            payload["assignee"] = colab_data["nominee"][0]
                    else:
                        payload["add_collaborators"] = json.dumps(colab_data)
                        # User changed authorization and transferred full ownership
                        if colab_data["auth_type"] == "Yes":
                            payload["assignee"] = colab_data["nominee"][0]
                            
            # # Sending notification email to both nominee and host
            # send_email_notification_to_staff(colab_data["nominee"][0])
                        
            serializer = TaskAssignmentManagerSerializer(queryset, data=payload, partial=True)
            if serializer.is_valid():
                serializer.save()
                log.info("Assignment with ID#%s has been updated", queryset.task_id)
                return Response(serializer.data, status=status.HTTP_200_OK)

            log.error(serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            log.exception("Error occurred while updating the task: %s", str(e))
            return Response({"error": "An error occurred while updating the task."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
      
      
############################################################################################################################

# Personal Journal

class PersonalJournalView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    # CREATE Note
    def post(self, request, id=None, *args, **kwargs):
        try:
            member_data = CustomUser.objects.get(id=id)
        except ClinicMember.DoesNotExist:
            log.warning("Invalid User ID provided")
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            # Making task structure
            check_list = []
            if request.data.get("check_list") is not None:
                for task in request.data.get("check_list"):
                    check_list.append({"task": task, "status": "Pending"})
                    
            reminder_data = request.data.get("reminder") 
            if reminder_data == "":
                reminder_data = None
                
            data = {"creator": request.data.get("creator"),
                    "label": str(request.data.get("label")).upper(),
                    "note_title": request.data.get("note_title"),
                    "note_content": request.data.get("note_content"),
                    "check_list": json.dumps(check_list, cls=DatetimeEncoder),
                    "reminder": reminder_data,
                    "archive_status": request.data.get("archive_status"),
            }
            
            serializer = PersonalJournalSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                log.info("Note created successfully")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        
            log.error(serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
    # VIEW Note
    def get(self, request, id=None, note_id=None, range=None, *args, **kwargs):
        try:
            member_data = CustomUser.objects.get(id=id)
        except CustomUser.DoesNotExist:
            log.warning("Invalid staff ID provided")
            return Response({"error": "Staff member not found."}, status=status.HTTP_404_NOT_FOUND)

        # Month error response
        if range is None or range == 'None':
            selected_month = datetime.date.today().month
            queryset = PersonalJournal.objects.filter(creator=id, created_on__month=selected_month).order_by("created_on")
            payload = apply_pagination(self, request, Paginator, queryset, PersonalJournalSerializer)
            return Response(payload, status=status.HTTP_200_OK)
        else:
            data = range.split('-')
            month_1 = int(data[0])
            month_2 = int(data[1])
        try:
            if note_id is None or note_id == 'None':
                # Fetch all PersonalJournal objects for the specified creator and selected month
                queryset = PersonalJournal.objects.filter(creator=id, created_on__month__range=[month_1, month_2]).order_by("created_on")
                if not queryset.exists():
                    # Sending an empty dictionary to the frontend to let them display No content message
                    payload = {}
                    return Response(payload, status=status.HTTP_204_NO_CONTENT)

                payload = apply_pagination(self, request, Paginator, queryset, PersonalJournalSerializer)
                return Response(payload, status=status.HTTP_200_OK)

            # If note_id is not None, then fetch data related to that note id
            journal_entry_data = get_object_or_404(PersonalJournal, creator=id, note_id=note_id)
            serializer = PersonalJournalSerializer(journal_entry_data)
            log.info("Journal Note ID#%s accessed successfully", note_id)

            return Response(serializer.data, status=status.HTTP_200_OK)
        except PersonalJournal.DoesNotExist:
            # Handle the case when the PersonalJournal object with the given note_id is not found
            return Response(data={"error": "PersonalJournal not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    #UPDATE Note
    def put(self, request, id=None, note_id=None, *args, **kwargs):
        try:
            member_data = CustomUser.objects.get(id=id)
        except ClinicMember.DoesNotExist:
            log.warning("Invalid User ID provided")
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            queryset = PersonalJournal.objects.get(note_id=note_id)
        except PersonalJournal.DoesNotExist:
            log.warning("Invalid Journal Entry ID provided.")
            return Response({"error": "Journal Entry not found."}, status=status.HTTP_404_NOT_FOUND)
        
        fetched_data = request.data
        
        # Updating threads If they are not null
        if fetched_data["check_list"] is not None:
            fetched_checklist = json.loads(fetched_data["check_list"])
            updated_checklist = json.dumps(fetched_checklist, cls=DatetimeEncoder)
                
        # Updating edit timeline 
        new_edit_timeline = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        loaded_meta_edit_timeline = json.loads(queryset.edit_timeline)
        loaded_meta_edit_timeline.append(new_edit_timeline)
        
        # Add new field to final payload
        payload = {
                    "note_content": fetched_data["note_content"],
                    "check_list": updated_checklist,
                    "edit_timeline": json.dumps(loaded_meta_edit_timeline, cls=DatetimeEncoder)
                    }

        serializer = PersonalJournalSerializer(queryset, data=payload, partial=True)
        if serializer.is_valid():
            serializer.save()
            log.info("Journal Entry %s updated successfully", note_id)
            return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

        log.error(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

      
        
############################################################################################################################

# Appointment view
class AppointmentManagement(APIView):
    permission_classes = [permissions.AllowAny]

    # Create a new Appointment
    def post(self, request):
        # Using request.body first to avoid django.http.request.RawPostDataException 
        # Request.body is being used by the faker data generator in json str/bytes data type 
        fetched_body = request.body
        # Request.data is being fetched by direct API credentials which is normally dict type
        fetched_data = request.data

        if isinstance(fetched_body, bytes):
            try:
                loaded_queryset = json.loads(json.loads(fetched_body))
            except json.JSONDecodeError:
                return Response({"error": "Invalid JSON data provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        elif isinstance(fetched_data, dict):
            loaded_queryset = {
            "clinic_name": fetched_data.get("clinic_name"),
            "relatedRecipient": fetched_data.get("relatedRecipient"), 
            "patient_first_name": fetched_data.get("patient_first_name"),
            "patient_last_name": fetched_data.get("patient_social_security_ID"),
            "patient_social_security_ID": fetched_data.get("patient_last_name"),
            "patient_gender": fetched_data.get("patient_gender"),
            "date_of_birth": fetched_data.get("date_of_birth"),
            "patient_consent_agreement": fetched_data.get("patient_consent_agreement"),
            "patient_contact_number": fetched_data.get("patient_contact_number"),
            "patient_email": fetched_data.get("patient_email"),
            "recurring_patient": fetched_data.get("recurring_patient"),
            "appointment_date": fetched_data.get("appointment_date"),
            "appointment_slot": fetched_data.get("appointment_slot"),
            "appointment_status": fetched_data.get("appointment_status"),
            "procedures": fetched_data.get("procedures")}

            # Fetching data
            queryset = ClinicMember.objects.filter(staff_id=loaded_queryset.get("relatedRecipient")).values(
                "staff_first_name", "staff_last_name", "staff_email", "staff_contact_number"
            ).first()

            # Sending Email Notifications
            send_email_notification_to_staff(queryset)
            send_email_notification_to_patient(loaded_queryset, queryset)
            log.info("Appointment creation notification email sent to both client and consultant.")

            # Sending SMS Notifications
            send_sms_notification_staff_member(queryset)
            send_sms_notification_patient(loaded_queryset, queryset)
            log.info("Appointment creation notification SMS sent to both client and consultant.")
            
        else:
            return Response({"error": "Invalid data provided"}, status=status.HTTP_406_NOT_ACCEPTABLE) 
        try:
            # Deserialize the data into an AppointmentSerializer
            serializer = AppointmentSerializer(data=loaded_queryset)

            if serializer.is_valid():
                # Save the serializer, creating a new appointment if it doesn't exist
                appointment_instance = serializer.save()

                if appointment_instance.procedures.count() == 0:
                    total_cost = 0
                    for procedure_name in loaded_queryset["procedures"]:
                        procedures = MedicalProceduresTypes.objects.filter(procedure_choice=procedure_name)
                        # Adding procedure_choice
                        appointment_instance.procedures.add(*procedures)
                        # Adding its fee
                        meta_data = procedures.values("fixed_cost").first()
                        total_cost += Decimal(meta_data["fixed_cost"])
                        
                appointment_instance.total_procedure_cost = total_cost.quantize(Decimal("0.00"))
                log.info("New Appointment has been created")
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
                queryset = PatientAppointment.objects.all().order_by("-created_at")

                # filter and Search function for list
                filter_params = {
                    "appointment_id": self.request.GET.get("appointment_id"),
                    "clinic_name": self.request.GET.get("clinic_name"),
                    "relatedDepartment": self.request.GET.get("relatedDepartment"),
                    "relatedRecipient": self.request.GET.get("relatedRecipient"),
                    "patient_email": self.request.GET.get("patient_email"),
                    "patient_contact_number": self.request.GET.get("patient_contact_number"),
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
                "client_shipping_address": self.request.GET.get("client_shipping_address"),
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
            
            date_list = []
            for client in queryset.values():
                transactions_details = client.get("transactions_made", {})
                if transactions_details:
                    try:
                        transactions_data = json.loads(transactions_details)
                    except Exception:
                        transactions_data = transactions_details
                    for data in transactions_data:
                        if data["stripe_payment_status"] == 'paid':
                            date_list.append(str(data["payment_due_date"]))
                            date_list.append(str(data["session_created_on"]))
                    else:
                        continue

            # stats
            total_patients_treated = Prescription.total_patients_treated()
            active_patients_data = Prescription.get_total_unique_active_patients_with_age_gender_distribution()
            paid_prescriptions = len(Prescription.objects.filter(payment_status="PAID").values())
            active_patients_count = active_patients_data["total_unique_active_patients"]
            patient_age_distribution = {
                "Children_distribution": active_patients_data["Children_distribution"], 
                "Teenagers_distribution": active_patients_data["Teenagers_distribution"], 
                "Adults_distribution": active_patients_data["Adults_distribution"]
                }
            patientGenderStats = {
                "Male_distribution": active_patients_data["Male_distribution"], 
                "Female_distribution": active_patients_data["Female_distribution"], 
                "Undisclosed_distribution": active_patients_data["Undisclosed_distribution"]
                }
            totalProcedureAmount = PatientAppointment.get_total_procedure_amount()
            totalAppointmentFees = Decimal(len(PatientAppointment.objects.values()) * 100).quantize(Decimal('0.00'))
            totalPrescriptionMedAmount = Prescription.get_total_due_amount()

            # Total prescription and appointments created for patients
            prescriptionCount = sum(int(prescription["prescription_count"]) for prescription in payload["Result"])
            appointmentCount = sum(int(appointment["appointment_count"]) for appointment in payload["Result"])
            totalBilling = sum(Decimal(revenue["total_billings"]) for revenue in payload["Result"])
            avg_payment_credit_time =  sum(days_diff(a, b) for a, b in zip(date_list, date_list[1:])) // (len(date_list) - 1)
            
            if Decimal(paid_prescriptions) != 0:
                averageBilling = totalBilling / Decimal(paid_prescriptions)
            else:
                averageBilling = 0
            
            # Adding a nest in the dictionary for respective variable
            payload["Dashboard_stats"] = {
                "total_medical_procedure_count": medProceduresCount,
                "total_prescriptions_created": prescriptionCount,
                "total_appointment_handled": appointmentCount,
                "active_patients_count": active_patients_count,
                "total_patients_treated": total_patients_treated,
                "patients_gender_distribution": patientGenderStats,
                "patients_age_distribution": patient_age_distribution,
                "total_pending_payment_amount": {"total_appointment_fee_collected": totalAppointmentFees, 
                                                 "total_procedure_fee_collected": totalProcedureAmount,
                                                 "total_prescription_med_fee_collected": totalPrescriptionMedAmount,
                                                 "total": (totalAppointmentFees + totalPrescriptionMedAmount + totalProcedureAmount)},
                "total_payment_revenue": totalBilling,
                "average_patient_treatment_cost": averageBilling,
                "avg_payment_credit_time": abs(round(avg_payment_credit_time, 2)),
            }
            log.info("Client data generated")
            return Response(payload, status=status.HTTP_200_OK,)
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


############################################################################################################################

# Drug Inventory 
class PharmacyInventoryManagement(APIView):
    permission_classes = [permissions.AllowAny]

    # ADD DRUG
    def post(self, request):
        try:
            # Deserialize the incoming JSON data
            loaded_queryset = json.loads(request.body)
            serializer = PharmacyInventorySerializer(data=loaded_queryset)
            if serializer.is_valid():
                serializer.save()
                log.info("New Drug added successfully")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            log.critical(serializer.errors)
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
    # View Drug List
    def get(self, request, drug_id=None, *args, **kwargs):
        try:
            if drug_id == 'None':
                drug_id = None
            queryset = PharmacyInventory.objects.all().order_by("-added_at")
            
            a_queryset = PatientAppointment.objects.all().order_by("-created_at")
            drug_list = []
            for inventory_item in a_queryset:
                drug_list.append(inventory_item.appointment_id)
            
            if drug_id is not None:
                queryset = queryset.filter(drug_id=drug_id)
                serializer = PharmacyInventorySerializer(queryset, many=True)
                log.info("Drug %s data fetched successfully", drug_id)
                return Response(serializer.data, status=status.HTTP_200_OK)

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


# Creating and send a request for New Batch Purchase
class SendBatchPurchaseRequest(APIView):
    # fetch selling projects
    stripe.api_key = STRIPE_SECRET_KEY
    permission_classes = [permissions.AllowAny]
    
    # CREATE PO
    def post(self, request, *args, **kwargs):
        try:
            cleaned_data = {
                "order": json.dumps(request.data.get("order")),
                "total_payment_amount": request.data.get("total_payment_amount"),
                "created_by": request.data.get("created_by"),
                "thread_history": json.dumps([request.data.get("thread_history")]),
                "request_sent_at": request.data.get("request_sent_at"),
                "status": request.data.get("status"),
            }

            items = request.data.get("order")
            user_id = request.data.get("created_by")
            
            try:
                user_data = CustomUser.objects.filter(id=user_id).values().first()
            except ObjectDoesNotExist:
                log.warning("User with id %s does not exist", user_id)
                return Response({"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND)

            serializer = PurchaseOrderSerializer(data=cleaned_data)
            if serializer.is_valid():
                purchase_order = serializer.save()
                # Specify the filename for the CSV file
                filename = f'purchase_order_{purchase_order.purchase_order_id}.csv'
                # Convert purchase order dictionary to csv file
                file_path = dict_to_csv(items, filename)
                # PurchaseOrder instance
                with open(file_path, 'rb') as file:
                    purchase_order.PO_report.save(filename, file)
                # Send an email with the CSV file containing the purchase order
                send_email_with_attachment(user_data, purchase_order, file=file_path)
                log.info("New Purchase Order created successfully. Email Sent.")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            log.error(str(serializer.errors))
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except ObjectDoesNotExist as e:
            log.error(str(e))
            return Response({"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # VIEW PO
    def get(self, request, purchase_order_id=None, *args, **kwargs):
        try:
            if purchase_order_id == 'None':
                purchase_order_id = None
            queryset = PurchaseOrder.objects.all().order_by("-request_sent_at")

            if purchase_order_id is not None:
                queryset = queryset.filter(purchase_order_id=purchase_order_id)
                serializer = PurchaseOrderSerializer(queryset, many=True)
                log.info("Batch PO ID %s data fetched successfully", purchase_order_id)
                return Response(serializer.data, status=status.HTTP_200_OK)

            # Filter and search function for list
            filter_params = {
                "purchase_order_id": self.request.GET.get("purchase_order_id"),
                "created_by": self.request.GET.get("created_by"),
                "status": self.request.GET.get("status"),
            }

            # Remove None values from filter_params
            filters = {field: value for field, value in filter_params.items() if value is not None}

            if filters:
                queryset = queryset.filter(**filters)

            # Applying pagination
            set_limit = self.request.GET.get("limit")
            paginator = Paginator(queryset, set_limit)
            page_number = self.request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            serializer = PurchaseOrderSerializer(page_obj, many=True)

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

            log.info("Batch Purchase Order data fetched successfully")
            return Response(payload, status=status.HTTP_200_OK)

        except PurchaseOrder.DoesNotExist:
            return Response(data={"error": "Batch Purchase Order not found"}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


    # UPDATE PURCHASE ORDER AND DRUG STOCK AFTER APPROVAL
    def get_user_data(self, user_id):
        try:
            user_data = CustomUser.objects.filter(id=user_id).values().first()
            return user_data
        except ObjectDoesNotExist:
            log.warning("User with id %s does not exist", user_id)
            return Response({"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND)
  
    def get_purchase_order(self, purchase_order_id):
        try:
            po_data = PurchaseOrder.objects.get(purchase_order_id=purchase_order_id)
            return po_data
        except ObjectDoesNotExist:
            log.warning("Purchase order Id %s does not exist", purchase_order_id)
            return Response({"error": "Purchase order Id not found."}, status=status.HTTP_404_NOT_FOUND)
    
    def add_new_product_to_inventory(self, queryset):
        try:
            drug_id = queryset.get("drug_id")
            product_data = stripe.Product.retrieve(drug_id)
            final_payload = json.dumps(extract_product_data(product_data), cls=DecimalEncoder)
            # URL of your Django post view
            post_view_url = f"{settings.YOUR_DOMAIN}/pharmacy/inventory/add/"
            headers = {"Content-Type": "application/json"}
            response = requests.post(post_view_url, data=final_payload, headers=headers)
            return response
        except Exception as e:
            print(e)
            return None
        
    def fetch_product_data_from_stripe(self, drug_id=None, seller_product_id=None):
        stripe.api_key = STRIPE_SECRET_KEY
        if drug_id:
            target_id = drug_id
        else:
            target_id = seller_product_id
        try:
            product_data = stripe.Product.retrieve(str(target_id))
            final_payload = extract_product_data(product_data)
            response = self.add_new_product_to_inventory(final_payload)
            
            if response.status_code == status.HTTP_201_CREATED:
                response_dict = json.loads(response.text)
                new_drug_id = response_dict.get('drug_id')
                print(f"Fetched id: {new_drug_id}")
                new_product_data = PharmacyInventory.objects.filter(drug_id=new_drug_id).values().first()
                return new_product_data
            elif response.status_code != status.HTTP_201_CREATED:
                log.debug("Error Code %s: New product didn`t added to inventory", response.status_code)
                return None
        except stripe.error.InvalidRequestError as stripe_error:
            log.debug("Error Code %s: stripe.error.InvalidRequestError", response.status_code)
            return Response({"error": str(stripe_error)}, status=status.HTTP_400_BAD_REQUEST)
    
        except Exception as e:
            log.exception("Error: {e}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def get_pharmacy_inventory(self, queryset):
        drug_name = queryset.get("drugName")
        drug_id = queryset.get("drugId")
        seller_product_id = queryset.get("seller_productId")
        try:
            product = PharmacyInventory.objects.filter(drug_id=drug_id).values().first()
            if product:
                return product
            queryset = PharmacyInventory.objects.all().order_by("-added_at")
            product = queryset.filter(drug_name=drug_name).values().first()
            if product:
                return product
            else:
                data = self.fetch_product_data_from_stripe(drug_id, seller_product_id)
                if data:
                    return data
                else:
                    return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
                
        except Exception as e:
            error_code = str(e)
            return Response({"error": error_code}, status=status.HTTP_404_NOT_FOUND)
        
    def update_thread_history(self, purchase_order, new_thread):
        meta_thread_history = json.loads(purchase_order.thread_history)
        meta_thread_history.append(new_thread)
        purchase_order.thread_history = json.dumps(meta_thread_history)
        purchase_order.save()
                     
    def get_total_payment_amount(self, order_data):
        total_payment_amount = 0
        for drug in order_data:
            total_payment_amount += Decimal(float(drug["pricePerUnit"]) * int(drug["quantity"])).quantize(Decimal('0.00'))
        return total_payment_amount

    def update_purchase_order(self, purchase_order, created_by, status_data, authorized_by, structured_data, thread_data):
        try:
            serializer = PurchaseOrderSerializer(purchase_order, data={
                "order": json.dumps(structured_data, cls=DecimalEncoder),
                "total_payment_amount": self.get_total_payment_amount(structured_data),
                "thread_history": json.dumps(thread_data),
                }, partial=True)

            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            elif authorized_by == "NA":
                purchase_order = serializer.save()
                new_thread = {
                    "log": "Purchase Order has been updated successfully.",
                    "user_id": created_by,
                    "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
                    }
                self.update_thread_history(purchase_order, new_thread)
                filename = f'Updated_{purchase_order.purchase_order_id}.csv'
                file_path = dict_to_csv(structured_data, filename)
                purchase_order.PO_report.save(filename, open(file_path, 'rb'))
                log.info("PO Updated successfully")
                purchase_order.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
                
            elif "SA-" in authorized_by and status_data == "APPROVED":
                purchase_order = serializer.save()
                purchase_order.approval_status = StatusCode.APPROVED
                purchase_order.authorized_by = authorized_by
                new_thread = {
                    "log": "Purchase Order has been accepted \n& Ready for Payment.",
                    "user_id": authorized_by,
                    "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                }
                self.update_thread_history(purchase_order, new_thread)
                filename = f'revised_{purchase_order.purchase_order_id}.csv'
                file_path = dict_to_csv(structured_data, filename)
                purchase_order.PO_report.save(filename, open(file_path, 'rb'))
                purchase_order.save()
                
                log.info("PO accepted and drug stock updated successfully")
                # Send email for revised accepted PO order
                user_data = self.get_user_data(authorized_by)
                send_email_with_attachment(user_data, purchase_order, file=file_path)
                log.info("Email for revised PO successfully")
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                Response({"error": "Invalid Instance"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @method_decorator(cache_page(60 * 15)) 
    # Cache the view for 15 minutes 
    def put(self, request, purchase_order_id, *args, **kwargs):
        purchase_order = self.get_purchase_order(purchase_order_id)
        if not purchase_order:
            return Response({"error": "Batch Purchase Order not found."}, status=status.HTTP_404_NOT_FOUND)
        
        # Checking PO already approved or not
        if purchase_order.approval_status == "APPROVED" and purchase_order.authorized_by != "NA":
            return Response({"warning": "PO already approved and can`t be modified."}, status=status.HTTP_423_LOCKED)

        created_by = request.data.get('created_by')
        order_data = request.data.get('order')
        approval_status_data = request.data.get('approval_status')
        authorized_by = request.data.get('authorized_by')
        thread_data = request.data.get('thread_history')

        if not isinstance(order_data, list):
            return Response({"error": "Invalid order data format. Expected a list."}, status=status.HTTP_400_BAD_REQUEST)

        structured_data = []
        for drug in order_data:
            drug_id = drug.get("drugId")
            drug_name = drug.get("drugName")
            drug_info = self.get_pharmacy_inventory(drug)
            if not drug_info:
                return Response({"error": f"Drug with ID {drug_id} does not exist."}, status=status.HTTP_404_NOT_FOUND)
            drug["drugURL"] = drug_info["drug_image_url"]
            drug["seller_productId"] = fetch_seller_product_id(drug_name)
            drug["priceId"] = fetch_stripe_price_id(drug_id, drug["seller_productId"])
            structured_data.append(drug)
        return self.update_purchase_order(purchase_order, created_by, approval_status_data, authorized_by, structured_data, thread_data)

    # DELETE
    def delete(self, request, purchase_order_id, *args, **kwargs):
        try:
            drug_data = PurchaseOrder.objects.get(purchase_order_id=purchase_order_id)
        except PurchaseOrder.DoesNotExist:
            log.warning("Invalid Purchase Order ID provided.")
            return Response({"error": "Batch Purchase Order not found."}, status=status.HTTP_404_NOT_FOUND)
        drug_data.delete()
        log.info("%s has been deleted successfully", purchase_order_id)
        return Response(data={"message": "PO deleted successfully"}, status=status.HTTP_204_NO_CONTENT,)


# PO THREAD COMMUNICATION AND LOG MANAGEMENT
class ThreadManagementView(APIView):
    permission_classes = [permissions.AllowAny]
    
    # UPDATE THREADS
    def put(self, request, purchase_order_id, *args, **kwargs):
        try:
            queryset = PurchaseOrder.objects.get(purchase_order_id=purchase_order_id)
        except PurchaseOrder.DoesNotExist:
            log.warning("Invalid Purchase Order ID provided.")
            return Response({"error": "Batch Purchase Order not found."}, status=status.HTTP_404_NOT_FOUND)
        
        new_custom_thread = request.data
        meta_thread = queryset.thread_history
        if len(meta_thread) != 0:
            loaded_meta_thread = json.loads(meta_thread)
            loaded_meta_thread.append(new_custom_thread)       
            update_data = {"thread_history": json.dumps(loaded_meta_thread)}
        else:
            loaded_meta_thread = []
            loaded_meta_thread.append(new_custom_thread)
            update_data = {"thread_history": json.dumps(loaded_meta_thread)}
        
        serializer = PurchaseOrderSerializer(queryset, data=update_data, partial=True)
        if serializer.is_valid():
            serializer.save()
            log.info("%s updated successfully", purchase_order_id)
            return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

        log.error(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Download Revised Invoice for PO
class DownloadPOInvoices(APIView):
    def get(self, request, purchase_order_id, *args, **kwargs):
        try:
            purchase_order = PurchaseOrder.objects.filter(purchase_order_id=purchase_order_id).values().first()
            if not purchase_order:
                return Response(data={"error": "Purchase Order not found."}, status=status.HTTP_404_NOT_FOUND)
            json_file = purchase_order["order"]
            formatted_file = json.loads(json_file)
            # Creating custom csv file
            filename = f'RequestOrder_{purchase_order_id}.csv'
            file_path = dict_to_csv(formatted_file, filename)
            # Set the appropriate response headers
            response = FileResponse(open(file_path, 'rb'), content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)



############################################################################################################################

# Prescription Creation View
class PrescriptionManagement(APIView):
    permission_classes = [permissions.AllowAny]

    # Add Prescription
    def post(self, request):
        fetched_body = request.body
        # Request.data is being fetched by direct API credentials which is normally dict type
        fetched_data = request.data

        if isinstance(fetched_body, bytes):
            try:
                loaded_queryset = json.loads(json.loads(fetched_body))
            except json.JSONDecodeError:
                return Response({"error": "Invalid JSON data provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        elif isinstance(fetched_data, dict):
            loaded_queryset = {
            "appointment_id": request.data.get("appointment_id"),
            "medications_json": request.data.get("medications_json"),
            "shipping_address": request.data.get("shipping_address"),
            "coupon_discount": request.data.get("coupon_discount"),
            "description": request.data.get("description"),
            "created_at": request.data.get("created_at"),}
        
        updated_medications_json = {}
        try:
            log.debug("Medications data fetching")
            for med in loaded_queryset["medications_json"]:
                quantity = med['quantity']
                drug_id = med['drug_id']
                dosage_freq = med['dosage_freq']
                verified_data = PharmacyInventory.objects.get(drug_id=drug_id)
                
                if drug_id in updated_medications_json:
                    # If the drug_id is already in the dictionary, add the quantity
                    updated_medications_json[drug_id]['quantity'] += quantity
                    # Calculate the new total_payable_amount
                    updated_medications_json[drug_id]['total_payable_amount'] += Decimal(float(verified_data.price) * float(quantity)).quantize(Decimal('0.00'))
                else:
                    # If the drug_id is not in the dictionary, create a new entry
                    medication = {
                        "medicine_id": verified_data.drug_id,
                        "medicine_name": verified_data.drug_name,
                        "purpose": verified_data.drug_class,
                        "quantity": quantity,
                        "amount_per_unit": verified_data.price,
                        "total_payable_amount": Decimal(float(verified_data.price) * float(quantity)).quantize(Decimal('0.00')),
                        "stripe_price_id": verified_data.stripe_price_id,
                        "dosage_freq": dosage_freq
                    }
                    updated_medications_json[drug_id] = medication

            # Convert the dictionary back to a list
            updated_medications_json = list(updated_medications_json.values())

        except PharmacyInventory.DoesNotExist as p:
            log.warning("Invalid Drug ID provided")
            return Response({"error": "PharmacyInventory with drug_id {} does not exist.".format(drug_id)}, 
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.critical(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        # Converting nested list to valid json format
        loaded_queryset["medications_json"] = json.dumps(updated_medications_json, cls=DecimalEncoder)
        
        # validate shipping address
        verified_address = validate_address(loaded_queryset["shipping_address"][0])
        loaded_queryset["shipping_address"] = json.dumps(verified_address)
  
        # Finally validating through serializer
        serializer = PrescriptionSerializer(data=loaded_queryset)
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
                "stripe_client_id": self.request.GET.get("stripe_client_id"),
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
            
            for prescription in serializer.data:
                prescription_id = prescription["prescription_id"]
                gender = Prescription.get_customer_data(prescription_id)
                prescription["client_gender"] = gender
            
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
        stripe_config = {'secret_key': settings.STRIPE_SECRET_KEY}
        log.warning("Stripe secret key triggered in frontend")
        return JsonResponse(stripe_config, safe=False)


# Stripe Payment API
class PrescriptionPaymentCheckoutSessionView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, prescription_id, *args, **kwargs):
        stripe.api_key = settings.STRIPE_SECRET_KEY
        try:
            # Fetch the data related to the unique prescription_id
            prescription_dict = fetch_master_data(appointment_id=None, prescription_id=prescription_id)
            log.info("Custom Data with PID %s generated", prescription_id)

            # Generate the line items for the checkout session
            items = create_payment_link(prescription_dict, return_items="line_items")
            log.info("Line items gathered")

            # Create or retrieve the Stripe customer
            customer_id = get_or_create_stripe_customer(prescription_dict)

            # Create a checkout session with Stripe
            checkout_session = stripe.checkout.Session.create(
                success_url=settings.YOUR_DOMAIN + "/payment/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=settings.YOUR_DOMAIN + "/payment/cancel",
                customer=customer_id,
                payment_method_types=["card"],
                mode="payment",
                currency='usd',
                line_items=items,
                client_reference_id=prescription_id,
                billing_address_collection="required")
            
            log.info("Checkout session created successfully")
            # Generate the payment link from Stripe
            payment_url = checkout_session.url

            # PayLink sanity Check
            if payment_url is None:
                log.critical("Failed to create a payment link")
                return Response(
                    data={"error": "Failed to create a payment link"}, status=status.HTTP_400_BAD_REQUEST,)

            # Send the payment link to the client via email
            send_pay_link_via_email(prescription_dict, payment_url)
            log.info("Payment link shared with the client via email")

            return Response({"sessionId": checkout_session.id, "payment_link": payment_url})
        #error handling
        except stripe.error.StripeError as e:
            log.error(str(e))
            return Response(data={"Stripe error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.error(str(e))
            return Response(data={"Internal error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Success View
class SuccessPaymentView(View):
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        stripe.api_key = settings.STRIPE_SECRET_KEY
        session_id = request.GET.get('session_id')

        try:
            session_data = stripe.checkout.Session.retrieve(session_id)
            log.info("Session Data retrieved")
            # Cleaning data
            cleaned_session_data = clean_payment_data(session_data)
            cleaned_data = {
                'prescription_id': cleaned_session_data["client_reference_id"],
                'session_id': cleaned_session_data["id"],
                'payment_intent': cleaned_session_data["payment_intent"],
                'bill_amount': Decimal((int(cleaned_session_data["amount_total"])/100)).quantize(Decimal('0.00')),
                'payment_method': cleaned_session_data["payment_method_types"][0],
                'client_billing_address': json.loads(json.dumps(cleaned_session_data["customer_details"]["address"])),
                'stripe_session_status': cleaned_session_data["status"],
                'stripe_payment_status': cleaned_session_data["payment_status"],
                'session_created_on': datetime.fromtimestamp(cleaned_session_data["created"]).strftime("%d-%m-%Y %H:%M:%S"),
                'session_expired_on': datetime.fromtimestamp(cleaned_session_data["expires_at"]).strftime("%d-%m-%Y %H:%M:%S"),
            }

            with transaction.atomic():
                prescription_id = cleaned_data["prescription_id"]
                try:
                    prescription = Prescription.objects.get(prescription_id=prescription_id)
                    timestamp = prescription.created_at
                    datetime_obj = datetime.strptime(str(timestamp), "%Y-%m-%d %H:%M:%S")
                    formatted_datetime = datetime_obj.strftime("%d-%m-%Y %H:%M:%S")
                    cleaned_data["payment_due_date"] = formatted_datetime
                except Prescription.DoesNotExist:
                    return JsonResponse({'error': f"Prescription with ID {prescription_id} does not exist!"}, status=status.HTTP_400_BAD_REQUEST)

                try:
                    # Update billing address and customer ID in the related client object
                    client = ClientDataCollectionPool.objects.get(stripe_customer_id=cleaned_session_data["customer"])
                    client.client_billing_address = cleaned_data["client_billing_address"]
                    transaction_data = client.transactions_made
                    transaction_data.append(cleaned_data)
                    client.transactions_made = json.dumps(transaction_data, cls=DecimalEncoder)
                    client.total_billings = Decimal(float(client.total_billings) 
                                                    + float(cleaned_data['bill_amount'])).quantize(Decimal('0.00'))
                    client.save()

                    # Save the payment data
                    serializer = ClientDataCollectionPoolSerializer(client, data=cleaned_data, partial=True)
                    if serializer.is_valid():
                        serializer.save()
                        log.info("Payment data saved for client %s", session_data["customer"])
                        
                except ClientDataCollectionPool.DoesNotExist:
                    log.critical("client data for CID %s not found", session_data["customer"])
                    return JsonResponse({'error': "Customer not found"}, status=status.HTTP_400_BAD_REQUEST)

                # Update payment status in the related prescription
                prescription_data = {"payment_status": cleaned_data["stripe_payment_status"].upper()}
                prescription_serializer = PrescriptionSerializer(prescription, data=prescription_data, partial=True)
                if prescription_serializer.is_valid():
                    prescription_serializer.save()
                    log.info("Payment status updated for PID: %s", prescription_id)

            # Render success payment page with Customer Satisfaction Feedback form
            context = {'retrieve_session_data': cleaned_data}
            html_content = render_to_string('Success.html', context)
            log.info("Success payment page rendered")
            return HttpResponse(html_content, status=status.HTTP_200_OK)
        #Error handling
        except stripe.error.StripeError as e:
            error_message = "A payment error occurred: {}".format(e.user_message)
            log.critical(f'error : {str(error_message)}')
            return JsonResponse({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.error(f'error : {str(e)}')
            return JsonResponse({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# Post payment Customer Feedback redirect View
class CustomerFeedbackView(APIView):
    permission_classes = [permissions.AllowAny]

    # Create feedback
    def post(self, request, *args, **kwargs):
        try:
            data = {
                "cus_id": request.data.get("cus_id"),
                "session_id": request.data.get("session_id"),
                "overall_rating": request.data.get("overall_rating"),
                "comment": request.data.get("comment"),}
            
            if data["session_id"] is not None:
                session_id = data["session_id"]
                try:
                    session_data = stripe.checkout.Session.retrieve(session_id)
                    # adding customer id to data 
                    data["customer_id"] = str(session_data["customer"])
                    # Deleting session Id as its not necessary
                    del data['session_id']
                    
                    serializer = ClientServiceFeedbackSerializer(data=data, partial=True)
                    serializer.is_valid(raise_exception=True)
                    serializer.save()
                    log.info("CID %s has submitted his feedback successfully", data["customer_id"])
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
                except ValueError as v:
                    log.error(v)
                    # Get the customer data or return a 404 response if not found.
                    customer_id = data["cus_id"]
                    customer_data = get_object_or_404(ClientDataCollectionPool, stripe_customer_id=customer_id)
                    # Deleting session Id as its not necessary
                    del data['session_id']
                    
                    # Initialize the serializer and save the data in one step.
                    serializer = ClientServiceFeedbackSerializer(customer_data, data=data, partial=True)
                    serializer.is_valid(raise_exception=True)
                    serializer.save()
                    
                    log.info("CID %s has submitted their feedback successfully", customer_id)
                
            log.warning("Unable to retrieve Session ID")
            raise ValueError("Session ID is not available")
        
        except stripe.error.StripeError as e:
            error_message = str(e.user_message) if hasattr(e, "user_message") else str(e)
            log.error("Error from stripe API: %s", error_message)
            return Response({"error": error_message}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            log.error("error: %s", str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # View customer feedback
    def get(self, request, *args, **kwargs):
        try:
            queryset = ClientServiceFeedback.objects.all().order_by("-created_at")
            filter_params = {
                "customer_id": self.request.GET.get("customer_id"),
                "overall_rating": self.request.GET.get("overall_rating"),
                "comment": self.request.GET.get("comment"),
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
            serializer = ClientServiceFeedbackSerializer(page_obj, many=True)

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
            log.info("Feedback data generated")
            return Response(payload, status=status.HTTP_200_OK,)

        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
# Cancel Response View
class CancelPaymentView(View):
    def get(self, request):
        stripe.api_key = settings.STRIPE_SECRET_KEY
        html_content = render_to_string('Cancel.html')
        return HttpResponse(html_content)


############################################################################################################################

# Budget Planning
class FinancialBudgetView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    # CREATE 
    def post(self, request, *args, **kwargs):
        try:
            data = {
                "created_by": request.data.get("created_by"),
                "budget_title": request.data.get("budget_title"),
                "budget_period_type": request.data.get("budget_period_type"),
                "start_date": request.data.get("start_date"),
                "end_date": request.data.get("end_date"),
                "set_amount": request.data.get("set_amount"),
            }
            
            try:
                user_data = CustomUser.objects.filter(id = data["created_by"]).values().first()
            except ObjectDoesNotExist:
                log.warning("User with id %s does not exist", data["created_by"])
                return Response({"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND)

            serializer = FinancialBudgetSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                log.info("New plan added successfully")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            log.critical(serializer.errors)
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # VIEW
    def get(self, request, *args, **kwargs):
        try:
            queryset = FinancialBudget.objects.all().order_by("start_date")
            # Filter by query parameters
            budget_id = self.request.GET.get("budget_id")
            created_by = self.request.GET.get("created_by")
            if created_by:
                queryset = queryset.filter(created_by__icontains=created_by)
            if budget_id:
                queryset = queryset.filter(id=budget_id)
            # Applying pagination
            set_limit = int(self.request.GET.get("limit"))
            paginator = Paginator(queryset, set_limit)
            page_number = int(self.request.GET.get("page"))
            # Use GET instead of data to retrieve the page number
            page_obj = paginator.get_page(page_number)
            serializer = FinancialBudgetSerializer(page_obj, many=True)

            # result dictionary
            payload = {
                "Page": {
                    "totalRecords": queryset.count(),
                    "current": page_obj.number,
                    "next": page_obj.has_next(),
                    "previous": page_obj.has_previous(),
                    "totalPages": page_obj.paginator.num_pages,
                },
                "Result": serializer.data
                ,
            }
            log.info("All Budget plan Data fetched Successfully")
            return Response(payload, status=status.HTTP_200_OK,)
        except Exception as e:
            log.error(str(e))
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# Financial Data collection

class BudgetEvaluation(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_user_data(self, user_id):
        try:
            user_data = CustomUser.objects.filter(id=user_id).values().first()
            return user_data
        except ObjectDoesNotExist:
            log.warning("User with id %s does not exist", user_id)
            return Response({"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND)
    
    def validate_and_update_financial_budget(self, fetched_budget_id):
        try:
            budgetData = FinancialBudget.objects.get(budget_id=fetched_budget_id)
            evaluation_status = bool(budgetData.approved_by)
            updates = {"evaluation_status": evaluation_status}
            serializer = FinancialBudgetSerializer(budgetData, data=updates, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
        except FinancialBudget.DoesNotExist:
            return Response({'error': "Budget ID not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({'error': "Failed to update evaluation status"}, status=status.HTTP_400_BAD_REQUEST)
    
    def apply_daterange_filter(self, model, serializer, object_data, date_field):
        queryset = model.objects.all().order_by(date_field)
        serialized_data = serializer(queryset, many=True)
        normalized_data = json.loads(json.dumps(serialized_data.data, cls=DatetimeEncoder))
        # Convert start_date and end_date to timezone-aware datetime objects
        start_date = timezone.datetime.strptime(str(object_data["start_date"]), "%Y-%m-%d")
        end_date = timezone.datetime.strptime(str(object_data["end_date"]), "%Y-%m-%d")
        try:
            filtered_results = [
                object for object in normalized_data
                if start_date <= datetime.strptime(object[date_field], "%Y-%m-%d %H:%M:%S.%f") <= end_date]
        except Exception as e:
            log.info(f"Exception Case triggered: {e}")
            filtered_results = [object for object in normalized_data 
                                if start_date <= convert_string_date_django_datetime_format(object[date_field]) <= end_date]
        return filtered_results
                 
    def filter_paid_prescription(self, filtered_data, sub_field):
        paid_results = [data for data in filtered_data if data[sub_field] == "PAID"]
        return paid_results
               
    def filter_paid_appointments(self, filtered_data, sub_field):
        paid_procedure_data = []
        appointment_list = [data[sub_field] for data in filtered_data]
        for element in appointment_list:
            object = PatientAppointment.objects.filter(appointment_id=element).values().first()
            paid_procedure_data.append(object)
        return paid_procedure_data
        
    def get_total_amount(self, model_data, field):
        if len(model_data) != 0:
            try:
                total_income = model_data.aggregate(total_income=Sum(field))['total_income']
                return total_income or Decimal('0.00')
            except AttributeError as e:
                log.info(f"Exception Case triggered: {e}")
                total_income = sum(Decimal(obj[field]) for obj in model_data)
                return total_income or Decimal('0.00')
        return Decimal('0.00')
            
    def get_distribution_ratio(self, total, sub_total):
        if sub_total != 0 and total != 0:
            ratio = Decimal((sub_total / total) * 100)
            return round(ratio, 1) 
        return Decimal('0.0')

    def calculate_margin_rate(self, revenue, expenditure):
        if revenue != 0:
            return round(((revenue - expenditure) / revenue) * 100, 2)
        return Decimal('0.00')
        
    def evaluate_financial_data(self, budget_object): 
        # Filter the prescription model
        prescription_data = self.apply_daterange_filter(Prescription, PrescriptionSerializer, budget_object, 'created_at')
        paid_prescription_data = self.filter_paid_prescription(prescription_data, 'payment_status')
        med_prescription_fee = self.get_total_amount(paid_prescription_data, "med_bill_amount")
        patient_appointment_fee = Decimal(len(paid_prescription_data) * 100)  
        # Filter the PatientAppointment model with the date range
        paid_appointment_data = self.filter_paid_appointments(paid_prescription_data, 'appointment_id')
        med_procedure_fee = self.get_total_amount(paid_appointment_data, "total_procedure_cost")
        # We will assure that Hospital received donation which 5%-10% of the total budget
        # Also set limit for received donation is 6 which can be modified
        donation_data = self.apply_daterange_filter(Donations, DonationSerializer, budget_object, 'donation_date')
        donation_income = self.get_total_amount(donation_data, "donation_amount")
        # Employee salary
        employee_data = ClinicMember.objects.all()
        aggregate_emp_salary = self.get_total_amount(employee_data, "staff_fixed_salary")
        # Pharmacy Purchase Orders
        purchase_order_data = self.apply_daterange_filter(PurchaseOrder, PurchaseOrderSerializer, budget_object, 'request_sent_at')
        po_expense_amount = self.get_total_amount(purchase_order_data, "total_payment_amount")
        # Assuming Facility cost would be 20-30% of the total budget
        facility_costs = Decimal(float(budget_object["set_amount"]) * 0.25)
        # Final Stats
        final_total_revenue = sum([
            patient_appointment_fee, 
            med_procedure_fee, 
            med_prescription_fee, 
            donation_income
        ])
        final_total_expenditure = sum([
            aggregate_emp_salary, 
            po_expense_amount, 
            facility_costs
        ])
        margin_rate = self.calculate_margin_rate(final_total_revenue, final_total_expenditure)
        # Final Payload
        payload = {
            "budget_data": {"budget_id": budget_object["budget_id"],
                          "budget_title": budget_object["budget_title"],
                          "start_date": budget_object["start_date"],
                          "end_date": budget_object["end_date"],
                          "set_amount": budget_object["set_amount"]},
            "revenue_data": {
                "appointment_revenue": patient_appointment_fee,
                "appointment_ratio": self.get_distribution_ratio(final_total_revenue, patient_appointment_fee),
                "med_prescription_revenue": med_prescription_fee,
                "med_prescription_ratio": self.get_distribution_ratio(final_total_revenue, med_prescription_fee),
                "med_procedure_revenue": med_procedure_fee,
                "med_procedure_ratio": self.get_distribution_ratio(final_total_revenue, med_procedure_fee),
                "donation": donation_income,
                "donation_ratio": self.get_distribution_ratio(final_total_revenue, donation_income),
                "total_revenue": final_total_revenue,
            },
            "expenditure_data": {
                "emp_salary": aggregate_emp_salary,
                "emp_salary_ratio": self.get_distribution_ratio(final_total_expenditure, aggregate_emp_salary),
                "po_expense": po_expense_amount,
                "po_expense_ratio": self.get_distribution_ratio(final_total_expenditure, po_expense_amount),
                "facility_costs": facility_costs,
                "facility_cost_ratio": self.get_distribution_ratio(final_total_expenditure, facility_costs),
                "total_expenditure": final_total_expenditure
            },
            "margin_rate": str(margin_rate)}
        return payload
        
    def default_payload(self, fetched_budget_id):
        return {
            "budget_id": fetched_budget_id,
            "revenue_data": {
                "appointment_revenue": 0.00,
                "appointment_ratio": 0.00,
                "med_prescription_revenue": 0.00,
                "med_prescription_ratio": 0.00,
                "med_procedure_revenue": 0.00,
                "med_procedure_ratio": 0.00,
                "donation": 0.00,
                "donation_ratio": 0.00,
                "total_revenue": 0.00,
            },
            "expenditure_data": {
                "emp_salary": 0.00,
                "emp_salary_ratio": 0.00,
                "po_expense_ratio": 0.00,
                "po_expense_ratio": 0.00,
                "facility_costs": 0.00,
                "facility_cost_ratio": 0.00,
                "total_expenditure": 0.00,
            },
            "margin_rate": str(0.00),
            "approved_by": api_data["approved_by"],
        }    
        
    # CREATE THE BUDGET EVALUATION REPORT
    def get(self, request, budget_id, *args, **kwargs):
        try:
            start_time = time.time()
            if budget_id is not None: 
                fetched_budget_id = budget_id
                # Update evaluation status as its been approved
                budget_instance = self.validate_and_update_financial_budget(fetched_budget_id)
                # if response status is 200 then only provide financial evaluation data
                if budget_instance.status_code == 200:
                    verified_budget_object = FinancialBudget.objects.filter(budget_id=fetched_budget_id).values().first()
                    payload = self.evaluate_financial_data(verified_budget_object)
                    # Saving the data in cache 15 mins
                    cache.set(f"fetched_budget_{fetched_budget_id}", payload, 60*15)
                    # finally Checking function runtime
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    log.info(f"Financial Evaluation of completed in {elapsed_time:.3f} seconds")
                    return Response(payload, status=status.HTTP_200_OK)
                payload = self.default_payload(fetched_budget_id)
                log.warning(f"Financial Evaluation Incomplete due to unapproved Budget Plan")
                log.info(f"Process Timeout: {elapsed_time:.3f} seconds")
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            return Response({"error": "Budget ID not received"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

        
        
        
    
    




        
        
        
        
