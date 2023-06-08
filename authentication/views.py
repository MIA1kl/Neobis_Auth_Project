from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import render
from rest_framework import generics, status, views, permissions
from .serializers import ResetPasswordEmailRequestSerializer, EmailVerificationSerializer, LoginSerializer, \
    SetNewPasswordSerializer, RegisterEmailSerializer, RegisterPersonalInfoSerializer, RegisterPasswordSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, Hash
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRenderer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.http import HttpResponsePermanentRedirect
import os
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils import timezone

from django.urls import reverse
from .utils import Util
import uuid
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from datetime import datetime, timedelta
from urllib.parse import quote_plus


class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']


class RegisterEmailView(generics.GenericAPIView):
    serializer_class = RegisterEmailSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        email_data = request.data
        serializer = self.serializer_class(data=email_data)
        serializer.is_valid(raise_exception=True)

        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user)
        access_token = token.access_token
        access_token.lifetime = access_token.lifetime - timedelta(minutes=10)
        access_token.set_exp()

        token_hash = uuid.uuid4()

        print(Hash.objects.create(user=user, hash=token_hash))


        #token_payload = {'email': user.email}
        #token['email'] = user.email
        #token['payload'] = token_payload
        #token = str(token.access_token)

        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')
        absurl = 'http://' + current_site + relativeLink + "?token=" + str(token_hash)
        email_body = 'Hi ' + ' Use the link below to verify your email \n' + absurl
        data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}

        Util.send_email(data)

        # Store the user's email in the session
        # request.session['email'] = user.email
        # request.session.save()

        return Response(data={'access_token': str(access_token)}, status=status.HTTP_200_OK)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer
    authentication_classes = []

    def get(self, request):
        token_hash = request.GET.get('token')
        try:
            token = request.META.get('HTTP_AUTHORIZATION')
            token = token[7:]
            print(token_hash, token)
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256', options={"verify_exp": False})
            user_id = payload['user_id']
            # email = payload['email']

            token_hash_obj = Hash.objects.filter(hash = token_hash).first()
            print(token_hash_obj)
            if not token_hash_obj:
                return Response({'error': 'Invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)

            #token lifetime from its creation. Change timedelta parameters to change duration
            if token_hash_obj.created_at + timedelta(minutes=10) < timezone.now():
                return Response({'error': 'Activation link has expired'}, status=status.HTTP_400_BAD_REQUEST)


            user = User.objects.filter(id=user_id).first()

            if not user:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            if user.id == token_hash_obj.user.id:
                user.is_verified = True
                user.save()
                token_hash_obj.delete()
                return Response({'detail': 'Email successfully activated'}, status=status.HTTP_200_OK)



            # user_email = request.session.get('email')

            # Redirect to the personal info registration page
            # return redirect('http://localhost:3000/userinfo')
            # return redirect(reverse('register-personal-info') + f'?email={user_email}')

            return Response({'error': 'Invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)

        except (jwt.exceptions.DecodeError, User.DoesNotExist):
            return Response({'error': 'Invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)


from django.shortcuts import redirect


class RegisterPersonalInfoView(views.APIView):
    serializer_class = RegisterPersonalInfoSerializer
    authentication_classes = []

    def put(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION')
            token = token[7:]
            token = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256', options={"verify_exp": False})
        except jwt.exceptions.DecodeError:
            return Response({'error': 'You must pass email verification'}, status=status.HTTP_400_BAD_REQUEST)

        user_email = request.data.get('email')
        user = User.objects.filter(id=token['user_id']).first()
        # session_email = request.session.get('email')

        # Check if both email values are present and match
        if not user:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        if user_email != user.email:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        if not user.is_verified:
            return Response({'error': 'Email not verified'}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_reg_personal_info:
            return Response(data={'error': 'User already registered personal_info'}, status=status.HTTP_202_ACCEPTED)
        # try:
        #     # Retrieve the user using the email
        #     user = User.objects.get(email=user.email)
        # except User.DoesNotExist:
        #     return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = RegisterPersonalInfoSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            user.is_reg_personal_info = True
            user.save()

            # # Redirect to the password registration page
            # password_url = 'http://127.0.0.1:8000/auth/register/password/'
            # redirect_url = f"{password_url}?email={quote_plus(session_email)}"

            # # Remove the existing 'email' key from the session
            # if 'email' in request.session:
            #     del request.session['email']

            # return redirect(redirect_url)
            return Response(data=serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterPasswordView(views.APIView):
    serializer_class = RegisterPasswordSerializer
    authentication_classes = []
    @swagger_auto_schema(
        request_body=RegisterPasswordSerializer,
        responses={200: 'Password updated successfully', 400: 'Bad Request'}
    )
    def put(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION')
            token = token[7:]
            token = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256', options={"verify_exp": False})
        except jwt.exceptions.DecodeError:
            return Response({'error': 'You must pass email verification'}, status=status.HTTP_400_BAD_REQUEST)

        # user_email = request.GET.get('email')

        # try:
        #     # Retrieve the user using the email
        #     user = User.objects.get(email=email)
        # except User.DoesNotExist:
        #     return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        user = User.objects.filter(id=token['user_id']).first()
        if not user:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user's email is verified
        if not user.is_verified:
            return Response({'error': 'Email not verified'}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_reg_password:
            return Response(data={'error': 'User already registered password'}, status=status.HTTP_202_ACCEPTED)

        serializer = RegisterPasswordSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            user.is_reg_password = True
            user.save()
            return Response({'message': 'Password updated successfully'})
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            absurl = 'http://' + current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                         absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, try again'}, status=status.HTTP_400_BAD_REQUEST)
            return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token},
                            status=status.HTTP_200_OK)


        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, try again'}, status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset successfully'}, status=status.HTTP_200_OK)