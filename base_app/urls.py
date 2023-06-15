from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from .views import MyTokenObtainPairView, LogoutView
from .views import ClinicListView, StaffRelationshipManagementView
from .views import AppointmentManagement, PharmacyInventoryManagement, PrescriptionManagement
from .views import PingView, LoginView, SignupView, ForgotPasswordView, ResetPasswordView, UserRetrieveUpdateAPIView, VerifyOTPView
from .views import ResendOTP, PrescriptionPDFView




urlpatterns = [
    path('ping/', PingView.as_view(), name='ping'),
    
    path('login/', LoginView.as_view(), name='login'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('signup/verify/', VerifyOTPView.as_view(), name='auth_verify'),
    path('signup/verify/resend/', ResendOTP.as_view(), name='resend-otp'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('clinic/login/', LoginView.as_view(), name='login-clinic'),
    
    path('forgot-password/' , ForgotPasswordView.as_view(), name="forget-password"),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    
    path('profile/<str:id>/', UserRetrieveUpdateAPIView.as_view(), name='view'),
    path('profile/<str:id>/update/', UserRetrieveUpdateAPIView.as_view(), name='update'),
    path('profile/<str:id>/delete/', UserRetrieveUpdateAPIView.as_view(), name='delete'),
    
    path('clinic/add/', ClinicListView.as_view(), name="add-clinic"),
    path('clinic/list/', ClinicListView.as_view(), name="view-clinic"),
    path('clinic/delete/', ClinicListView.as_view(), name="delete-clinic"),
    
    path('clinic/allusers/', StaffRelationshipManagementView.as_view(), name='srm'),
    path('clinic/allusers/add/', StaffRelationshipManagementView.as_view(), name='srm-add'),
    
    path('clinic/scheduler/appointments/availability/', AppointmentManagement.as_view(), name='check-availability'),
    path('clinic/scheduler/appointments/create/', AppointmentManagement.as_view(), name='new-appointment'),
    path('clinic/scheduler/appointments/view/', AppointmentManagement.as_view(), name='view-appointment'),
    path('clinic/scheduler/appointments/update/<str:appointment_id>/', AppointmentManagement.as_view(), name='update-appointment'),
    path('clinic/scheduler/appointments/delete/<str:appointment_id>/', AppointmentManagement.as_view(), name='delete-appointment'),
    
    path('clinic/scheduler/appointments/prescription/create/', PharmacyInventoryManagement.as_view(), name='new-drug'),
    path('clinic/scheduler/appointments/prescription/view/', PrescriptionManagement.as_view(), name='create-prescription'),
    path('prescription/download/<uuid:prescription_id>/', PrescriptionPDFView.as_view(), name='download-prescription'),
    
    path('pharmacy/inventory/add/', PharmacyInventoryManagement.as_view(), name='new-drug'),
    path('pharmacy/inventory/list/', PharmacyInventoryManagement.as_view(), name='view-drug-list'),

    path('api/token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/logout_token/', LogoutView.as_view(), name='logout_token'), 
]