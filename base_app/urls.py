from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from .views import MyTokenObtainPairView, LogoutView
from .views import ClinicListView, StaffRelationshipManagementView
from .views import AppointmentManagement
from .views import PingView, LoginView, SignupView, ForgotPasswordView, ResetPasswordView, UserRetrieveUpdateAPIView, VerifyOTPView
from .views import ResendOTP



urlpatterns = [
    path('ping/', PingView.as_view(), name='ping'),
    
    path('login/', LoginView.as_view(), name='login'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('signup/verify/', VerifyOTPView.as_view(), name='auth_verify'),
    path('signup/verify/resend/', ResendOTP.as_view(), name='resend-otp'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    path('profile/<str:id>/', UserRetrieveUpdateAPIView.as_view(), name='view'),
    path('profile/<str:id>/update/', UserRetrieveUpdateAPIView.as_view(), name='update'),
    path('profile/<str:id>/delete/', UserRetrieveUpdateAPIView.as_view(), name='delete'),
    
    path('forgot-password/' , ForgotPasswordView.as_view(), name="forget-password"),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    
    path('clinic/add/', ClinicListView.as_view(), name="add-clinic"),
    path('clinic/list/', ClinicListView.as_view(), name="view-clinic"),
    path('clinic/login/', LoginView.as_view(), name='login-clinic'),
    path('clinic/allusers/', StaffRelationshipManagementView.as_view(), name='srm'),
    path('clinic/allusers/add/', StaffRelationshipManagementView.as_view(), name='srm-add'),
    
    path('clinic/scheduler/appointments/create/', AppointmentManagement.as_view(), name='new-appointment'),
    path('clinic/scheduler/appointments/view/', AppointmentManagement.as_view(), name='view-appointment'),
    path('clinic/scheduler/appointments/update/<str:appointment_id>/', AppointmentManagement.as_view(), name='update-appointment'),
    path('clinic/scheduler/appointments/delete/<str:appointment_id>/', AppointmentManagement.as_view(), name='delete-appointment'),
    
    path('clinic/scheduler/appointments/availability/', AppointmentManagement.as_view(), name='check-availability'),

    path('api/token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/logout_token/', LogoutView.as_view(), name='logout_token'), 
]