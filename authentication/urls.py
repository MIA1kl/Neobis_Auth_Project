from django.urls import path
from .views import  VerifyEmail, LoginAPIView, PasswordTokenCheckAPI, RequestPasswordResetEmail,SetNewPasswordAPIView, RegisterPasswordSerializer, RegisterEmailSerializer, RegisterPersonalInfoSerializer
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)



urlpatterns = [
    path('email/', RegisterEmailSerializer.as_view(), name='email_verification'),
    path('personal-info/<str:hash>/', RegisterPersonalInfoSerializer.as_view(), name='personal_info'),
    path('password/<str:hash>/', RegisterPasswordSerializer.as_view(), name='password'),
    path('login/', LoginAPIView.as_view(), name="login"),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(), name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(),name='password-reset-complete'),
]
