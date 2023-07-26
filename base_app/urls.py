from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from . import views
from . import helper_functions
from .views import MyTokenObtainPairView, TokenRefreshView, LogoutView
from .views import ClinicListView, StaffRelationshipManagementView
from .views import AppointmentManagement, PharmacyInventoryManagement, PrescriptionManagement
from .views import PingTest, LoginView, SignupView, ForgotPasswordView
from .views import ResendOTP, ResetPasswordView, UserRetrieveUpdateAPIView, VerifyOTPView
from .views import FetchPrescriptReceipt, PrescriptionPaymentCheckoutSessionView, CancelPaymentView, SuccessPaymentView
from .views import ClientDataManagement, CustomerFeedbackView, SendBatchPurchaseRequest, ThreadManagementView
from .views import DownloadPOInvoices, TaskManager


urlpatterns = [
    path('ping/', PingTest.as_view(), name='check-ping'),
    path('token/refresh/', TokenRefreshView.as_view(), name='auto-refresh-acc-token'),
    
    path('login/', LoginView.as_view(), name='login'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('signup/verify', VerifyOTPView.as_view(), name='auth_verify'),
    path('signup/verify/resend', ResendOTP.as_view(), name='resend-otp'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('clinic/login/', LoginView.as_view(), name='login-clinic'),
    
    path('forgot-password/' , ForgotPasswordView.as_view(), name="forget-password"),
    path('reset-password', ResetPasswordView.as_view(), name='reset-password'),
    
    path('profile/id=<str:id>', UserRetrieveUpdateAPIView.as_view(), name='view'),
    path('profile/<str:id>/update', UserRetrieveUpdateAPIView.as_view(), name='update'),
    path('profile/<str:id>/delete', UserRetrieveUpdateAPIView.as_view(), name='delete'),
    
    path('clinic/add/', ClinicListView.as_view(), name="add-clinic"),
    path('clinic/list/', ClinicListView.as_view(), name="view-clinic"),
    path('clinic/delete/', ClinicListView.as_view(), name="delete-clinic"),
    
    path('clinic/allusers/', StaffRelationshipManagementView.as_view(), name='srm'),
    path('clinic/allusers/add/', StaffRelationshipManagementView.as_view(), name='srm-add'),
    
    path('task-manager/create/', TaskManager.as_view(), name='create-assignment'),
    path('task-manager/view/<str:staff_id>/<str:task_id>', TaskManager.as_view(), name='view-assignment'),
    path('task-manager/update/<str:task_id>', TaskManager.as_view(), name='update-assignment'),
    
    path('clinic/scheduler/appointments/availability/', AppointmentManagement.as_view(), name='check-availability'),
    
    path('client/view/', ClientDataManagement.as_view(), name='view-client-data'),
    path('clinic/scheduler/appointments/create/', AppointmentManagement.as_view(), name='new-appointment'),
    path('clinic/scheduler/appointments/view/', AppointmentManagement.as_view(), name='view-appointment'),
    path('clinic/scheduler/appointments/view/<str:appointment_id>/', AppointmentManagement.as_view(), name='view-specific-appointment'),
    path('clinic/scheduler/appointments/update/<str:appointment_id>/', AppointmentManagement.as_view(), name='update-appointment'),
    path('clinic/scheduler/appointments/delete/<str:appointment_id>/', AppointmentManagement.as_view(), name='delete-appointment'),
    
    path('clinic/scheduler/appointments/prescription/create/', PrescriptionManagement.as_view(), name='create-prescription'),
    path('clinic/scheduler/appointments/prescription/view/', PrescriptionManagement.as_view(), name='view-prescription'),
    
    path('prescription/fetch/appointment_id=<str:appointment_id>&prescription_id=<str:prescription_id>', FetchPrescriptReceipt.as_view(), name='upload-prescription'),
    path('finance/change-currency/current_selected_currency=<str:current_selected_currency>&target_currency=<str:target_currency>', helper_functions.get_currency_exchange_rates),
    path('finance/view-customer-feedback/', CustomerFeedbackView.as_view(), name='view-customer-feedback'),
    
    path('config/', views.stripe_config, name='share-key'),
    path('payment/create-checkout-session/<str:prescription_id>/', PrescriptionPaymentCheckoutSessionView.as_view(), name='create-checkout-session'),
    path('payment/success', SuccessPaymentView.as_view(), name='success-payment-view'),
    path('payment/success/get-customer-feedback/', CustomerFeedbackView.as_view(), name='customer-feedback'),
    path('payment/cancel', CancelPaymentView.as_view(), name='cancel-payment-view'),    
    
    path('pharmacy/inventory/add/', PharmacyInventoryManagement.as_view(), name='new-drug'),
    path('pharmacy/inventory/list/drug_id=<str:drug_id>', PharmacyInventoryManagement.as_view(), name='view-drug-list'),
    path('pharmacy/inventory/drug_id=<str:drug_id>', PharmacyInventoryManagement.as_view(), name='view-selected-drug'),
    path('pharmacy/inventory/send-request/', SendBatchPurchaseRequest.as_view(), name='purchase-request'),
    
    path('pharmacy/purchase-order/purchase_order_id=<str:purchase_order_id>', SendBatchPurchaseRequest.as_view(), name='view-purchase-request'),
    path('pharmacy/purchase-order/edit/purchase_order_id=<str:purchase_order_id>', SendBatchPurchaseRequest.as_view(), name='update-purchase-request'),
    path('pharmacy/purchase-order/update-thread/purchase_order_id=<str:purchase_order_id>', ThreadManagementView.as_view(), name='update-thread'),
    path('pharmacy/purchase-order/del/purchase_order_id=<str:purchase_order_id>', SendBatchPurchaseRequest.as_view(), name='delete-purchase-request'),
    path('pharmacy/download-PO-invoice/purchase_order_id=<str:purchase_order_id>', DownloadPOInvoices.as_view(), name='download-purchase-request'),
    
    path('api/token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/logout_token/', LogoutView.as_view(), name='logout_token'), 
]




