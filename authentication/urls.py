from django.urls import path
from .views import  VerifyEmail, LoginAPIView, PasswordTokenCheckAPI, RequestPasswordResetEmail,SetNewPasswordAPIView, RegisterPasswordView, RegisterEmailView, RegisterPersonalInfoView
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)



urlpatterns = [
    path('register/email/', RegisterEmailView.as_view(), name='email_verification'),
    path('register/personal-info/', RegisterPersonalInfoView.as_view(), name='register-personal-info'),
    path('register/password/', RegisterPasswordView.as_view(), name='password'),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('login/', LoginAPIView.as_view(), name="login"),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(), name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(),name='password-reset-complete'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
