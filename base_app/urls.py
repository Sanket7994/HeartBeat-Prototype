from django.urls import path, include
from .views import MyTokenObtainPairView, LogoutView
from .views import ClinicRoleSwitchAuth, AddClinicView, ClinicPaginationWithFilterView, StaffRelationshipManagementView
from .views import DrugInventoryManagement, AppointmentManagement
from .views import PingView, LoginView, SignupView, ForgotPasswordView, ResetPasswordView, UserRetrieveUpdateAPIView
from rest_framework_simplejwt.views import TokenRefreshView



urlpatterns = [
    path('ping/', PingView.as_view(), name='ping'),
    
    path('login/', LoginView.as_view(), name='login'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    path('profile/<str:id>/', UserRetrieveUpdateAPIView.as_view(), name='view'),
    path('profile/<str:id>/update/', UserRetrieveUpdateAPIView.as_view(), name='update'),
    path('profile/<str:id>/delete/', UserRetrieveUpdateAPIView.as_view(), name='delete'),
    
    path('forgot-password/' , ForgotPasswordView.as_view(), name="forget-password"),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    
    path('clinic/add/', AddClinicView.as_view(), name="add-clinic"),
    path('clinic/list/', ClinicPaginationWithFilterView.as_view(), name="view-clinic"),
    path('clinic/login/', ClinicRoleSwitchAuth.as_view(), name='login-clinic'),
    path('clinic/allusers/', StaffRelationshipManagementView.as_view(), name='srm'),
    path('clinic/allusers/add/', StaffRelationshipManagementView.as_view(), name='srm-add'),
    
    path('clinic/scheduler/appointments/create/', AppointmentManagement.as_view(), name='new-appointment'),
    path('clinic/scheduler/appointments/view/', AppointmentManagement.as_view(), name='view-appointment'),
    
    path('drug/add/', DrugInventoryManagement.as_view(), name="add-drug"),
    path('drug/list/', DrugInventoryManagement.as_view(), name="view-drug"),
    path('drug/update/<str:token>/', DrugInventoryManagement.as_view(), name='update-drug'),
    path('drug/delete/<str:token>/', DrugInventoryManagement.as_view(), name='delete-drug'),
    
    path('api/token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/logout_token/', LogoutView.as_view(), name='logout_token'), 
]