from django.http import JsonResponse
from django.db import connection
from .serializers import RegisterSerializer, LoginSerializer
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth.hashers import check_password
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import uuid
import datetime
import jwt
import json
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.urls import reverse
from elevateed_auth.tokens import custom_password_reset_token
from datetime import datetime

# User Registration View
@csrf_exempt  # This will disable CSRF protection for this view
def register_user(request):
    if request.method == 'POST':
        form_data = json.loads(request.body)  # Get the form data
        full_name = form_data['full_name']
        email = form_data['email']
        password = make_password(form_data['password'])
        role = form_data['role']
        user_id = uuid.uuid4()

        with connection.cursor() as cursor:
            try:
                cursor.execute(
                    "INSERT INTO users (id, full_name, email, password, role, created_at) VALUES (%s, %s, %s, %s, %s, NOW())",
                    [user_id, full_name, email, password, role]
                )
                return JsonResponse({'status': 'success', 'message': 'User registered successfully'})
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)})

# Generate JWT access token  
def create_jwt_token(user_id, full_name, email, role):
    payload = {
        'user_id': user_id,
        'full_name': full_name,
        'email': email,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),  # Token expiration time
        'iat': datetime.datetime.utcnow()  # Token issuance time
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token

# User Login View with JWT
@csrf_exempt  # This will disable CSRF protection for this view
def login_user(request):
    if request.method == 'POST':
        form_data = json.loads(request.body)  # Get the form data
        email = form_data['email']
        password = form_data['password']
        print(f"Email: {email}, Password: {password}")
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, full_name, email, password, role FROM users WHERE email = %s",
                [email]
            )
            user = cursor.fetchone()
            print(f"User: {user}")
            if user: 
                is_valid_password = check_password(password, user[3]) # Validate hashed password
                if is_valid_password:
                    user_id = str(user[0]) # Convert user id to string
                    full_name = user[1]
                    email = user[2]
                    role = user[4]
                    access_token = create_jwt_token(user_id, full_name, email, role)  # Passing user_id, full_name, email, and role
                    print(f"Access Token: {access_token}")
                    return JsonResponse({
                        'status': 'success',
                        'access_token': str(access_token),
                        'email': email,
                        'full_name': full_name,
                        'role': role
                    })
                else:
                    return JsonResponse({'status': 'error', 'message': 'Invalid password'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Invalid credentials'})

# Password Reset Request View
@csrf_exempt  # Disable CSRF protection for this view
def password_reset_request(request):
    if request.method == 'POST':
        form_data = json.loads(request.body)  # Get the form data
        email = form_data['email']

        with connection.cursor() as cursor:
            cursor.execute("SELECT id, email FROM users WHERE email = %s", [email])
            user = cursor.fetchone()

            if user:
                user_id = user[0]
                token = custom_password_reset_token.make_token(user_id)  # Generate token
                uidb64 = urlsafe_base64_encode(force_bytes(user_id))  # Encode user ID
                print(f"Token: {token}, UIDB64: {uidb64}")

                reset_link = request.build_absolute_uri(reverse('password_reset_confirm', kwargs={
                    'uidb64': uidb64,
                    'token': token
                }))  # Generate password reset URL
                print(f"Reset Link: {reset_link}")

                subject = 'Password Reset Request'
                message = f'Dear user,\n\nClick the following link to reset your password:\n{reset_link}\n\nBest regards,\nTeam ElevateEd'
                from_email = settings.DEFAULT_FROM_EMAIL
                recipient_list = [email]

                try:
                    send_mail(subject, message, from_email, recipient_list)
                    return JsonResponse({'status': 'success', 'message': 'Password reset link sent to your email'})
                except Exception as e:
                    return JsonResponse({'status': 'error', 'message': 'Failed to send email: ' + str(e)})
            else:
                return JsonResponse({'status': 'error', 'message': 'Email not found'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

# Password Reset Confirmation View
@csrf_exempt  # Disable CSRF protection for this view
def password_reset_confirm(request, uidb64, token):
    if request.method == 'POST':
        form_data = json.loads(request.body)  # Get the form data
        new_password = form_data['password']
        # print password reset form data
        print(f"New Password: {new_password}")

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))  # Decode the user ID

            with connection.cursor() as cursor:
                cursor.execute("SELECT id, email FROM users WHERE id = %s", [user_id])
                user = cursor.fetchone()

                if user:
                    # Get the timestamp from the token
                    token_timestamp = custom_password_reset_token._num_seconds(datetime.now())

                    # Check if the token has expired
                    if custom_password_reset_token.token_expired(token_timestamp):
                        return JsonResponse({'status': 'error', 'message': 'Token has expired'})

                    # Validate token
                    if custom_password_reset_token.check_token(user_id, token):
                        hashed_password = make_password(new_password)
                        cursor.execute("UPDATE users SET password = %s WHERE id = %s", [hashed_password, user_id])
                        return JsonResponse({'status': 'success', 'message': 'Password reset successfully'})
                    else:
                        return JsonResponse({'status': 'error', 'message': 'Invalid token or user ID'})

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

   