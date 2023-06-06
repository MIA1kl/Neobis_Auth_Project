# Neobis_Auth_Project
<!DOCTYPE html>
<html>
<body>
  <h1>API Documentation</h1>
  <h2>User Registration - Email</h2>
  <p><strong>Endpoint:</strong> /auth/register/email/</p>
  <p><strong>Method:</strong> POST</p>
  <p><strong>Request Body:</strong></p>
  <pre>{
  "email": "user@example.com"
}</pre>
  <p><strong>Response:</strong></p>
  <pre>{
  "email": "user@example.com"
}</pre>
  <p><strong>Description:</strong> This endpoint is used to register a user with their email address. The user will receive an email with a verification link to activate their account.</p>
  <h2>Email Verification</h2>
  <p><strong>Endpoint:</strong> /auth/verify-email/</p>
  <p><strong>Method:</strong> GET</p>
  <p><strong>Query Parameters:</strong></p>
  <ul>
    <li><strong>token:</strong> The verification token received in the email</li>
  </ul>
  <p><strong>Response:</strong></p>
  <pre>{
  "detail": "Email successfully activated"
}</pre>
  <p><strong>Description:</strong> This endpoint is used to verify the user's email address. The user should click on the verification link received in the email.</p>
  <h2>User Registration - Personal Information</h2>
  <p><strong>Endpoint:</strong> /auth/register/personal-info/</p>
  <p><strong>Method:</strong> PUT</p>
  <p><strong>Request Body:</strong></p>
  <pre>{
  "first_name": "John",
  "last_name": "Doe",
  "birth_date": "1990-01-01",
  "email": "user@example.com"
}</pre>
  <p><strong>Response:</strong></p>
  <p>HTTP 200 OK</p>
  <p><strong>Description:</strong> This endpoint is used to register the user's personal information after email verification. The user should provide their first name, last name, birth date, and email.</p>
  <h2>User Registration - Password</h2>
  <p><strong>Endpoint:</strong> /auth/register/password/</p>
  <p><strong>Method:</strong> PUT</p>
  <p><strong>Request Body:</strong></p>
  <pre>{
  "password": "newpassword",
  "password_repeat": "newpassword"
}</pre>
  <p><strong>Query Parameters:</strong></p>
  <ul>
    <li><strong>email:</strong> The email address of the user</li>
  </ul>
  <p><strong>Response:</strong></p>
  <pre>{
  "message": "Password updated successfully"
}</pre>
  <p><strong>Description:</strong> This endpoint is used to set the user's password after providing their personal information. The user should provide the new password and repeat it for confirmation.</p>
  <h2>User Login</h2>
  <p><strong>Endpoint:</strong> /auth/login/</p>
  <p><strong>Method:</strong> POST</p>
  <p><strong>Request Body:</strong></p>
  <pre>{
  "email": "user@example.com",
  "password": "password"
}</pre>
  <p><strong>Response:</strong></p>
  <pre>{
  "email": "user@example.com",
  "tokens": {
    "refresh": "refresh_token",
    "access": "access_token"
  }
}</pre>
  <p><strong>Description:</strong> This endpoint is used to authenticate the user and obtain access and refresh tokens for subsequent API requests.</p>
  <h2>Request Password Reset Email</h2>
  <p><strong>Endpoint:</strong> /auth/request-password-reset/</p>
  <p><strong>Method:</strong> POST</p>
  <p><strong>Request Body:</strong></p>
  <pre>{
  "email": "user@example.com"
}</pre>
  <p><strong>Response:</strong></p>
  <pre>{
  "success": "We have sent you a link to reset your password"
}</pre>
  <p><strong>Description:</strong> This endpoint is used to request a password reset email for the user. The user will receive an email with a link to reset their password.</p>
  <h2>Check Password Reset Token</h2>
  <p><strong>Endpoint:</strong> /auth/reset-password/check/{uidb64}/{token}/</p>
  <p><strong>Method:</strong> GET</p>
  <p><strong>Path Parameters:</strong></p>
  <ul>
    <li><strong>uidb64:</strong> The user ID encoded as base64</li>
    <li><strong>token:</strong> The password reset token</li>
  </ul>
  <p><strong>Response:</strong></p>
  <pre>{
  "success": true,
  "message": "Credentials Valid",
  "uidb64": "{uidb64}",
  "token": "{token}"
}</pre>
  <p><strong>Description:</strong> This endpoint is used to check the validity of a password reset token before setting a new password.</p>
  <h2>Set New Password</h2>
  <p><strong>Endpoint:</strong> /auth/reset-password/confirm/</p>
  <p><strong>Method:</strong> POST</p>
  <p><strong>Request Body:</strong></p>
  <pre>{
  "password": "newpassword",
  "token": "{token}",
  "uidb64": "{uidb64}"
}</pre>
  <p><strong>Response:</strong></p>
  <p>HTTP 200 OK</p>
  <p><strong>Description:</strong> This endpoint is used to set a new password for the user after successfully verifying the password reset token.</p>
  <p><strong>Note:</strong> Replace {uidb64} and {token} with the values received in the password reset email.</p>
</body>
</html>
