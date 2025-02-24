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
        'exp': datetime.utcnow() + timedelta(days=30),  # Token expiration time
        'iat': datetime.utcnow()  # Token issuance time
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
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from django.utils.timezone import now, timedelta
from django.conf import settings

# Store OTPs temporarily with expiration times
otp_storage = {}

def generate_otp():
    return get_random_string(length=6, allowed_chars='0123456789')

def send_otp_via_email(email, otp):
    subject = 'Password Reset OTP'
    message = f'Your OTP for password reset is {otp}. It will expire in 2 minutes.'
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

@csrf_exempt
def forgot_password_request(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')

        # Get user from the database (without Django ORM)
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, email FROM users WHERE email = %s", [email])
            user = cursor.fetchone()

        if user:
            otp = generate_otp()
            otp_expiration = now() + timedelta(minutes=2)

            # Save OTP and expiration time in otp_storage
            otp_storage[email] = {'otp': otp, 'expires_at': otp_expiration}
            
            # Send OTP to user's email
            send_otp_via_email(email, otp)

            return JsonResponse({'status': 'success', 'message': 'OTP sent to email.'})
        else:
            return JsonResponse({'status': 'error', 'message': 'User with this email does not exist.'})
    else:   
        return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})
    

@csrf_exempt
def verify_otp_and_reset_password(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        otp = data.get('otp')
        new_password = data.get('new_password')

        if email not in otp_storage:
            return JsonResponse({'status': 'error', 'message': 'No OTP request found for this email.'})

        stored_otp_info = otp_storage[email]
        stored_otp = stored_otp_info['otp']
        expires_at = stored_otp_info['expires_at']

        # Check if OTP matches and is not expired
        if otp == stored_otp and now() <= expires_at:
            # OTP is valid, update the password
            with connection.cursor() as cursor:
                hashed_password = make_password(new_password)
                cursor.execute("UPDATE users SET password = %s WHERE email = %s", [hashed_password, email])

            # Clear the OTP from storage after successful reset
            del otp_storage[email]

            return JsonResponse({'status': 'success', 'message': 'Password reset successfully.'})
        elif now() > expires_at:
            return JsonResponse({'status': 'error', 'message': 'OTP has expired.'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid OTP.'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})
    


   