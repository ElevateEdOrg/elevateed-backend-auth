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
import os
import boto3
from botocore.exceptions import NoCredentialsError, ClientError


# Function to upload avatar to S3 and return the S3 URL
def upload_to_s3(file, file_name):
    s3 = boto3.client('s3',
                      aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                      region_name=settings.AWS_S3_REGION_NAME,
                      config=boto3.session.Config(signature_version='s3v4'))
    
    # Define file size limit (5MB)
    file_size_limit = 5 * 1024 * 1024 # 5MB in bytes

    # Check if the file size exceeds the limit
    if file.size > file_size_limit:
        print(f"File size exceeds limit: {file.size} bytes")
        return {"error": "File size exceeds the maximum limit of 5MB."}

    try:
        s3.upload_fileobj(file, settings.AWS_STORAGE_BUCKET_NAME, file_name)
        s3_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{file_name}"
        print(f"File uploaded to S3: {s3_url}")  # Printing the URL 
        return s3_url
    except NoCredentialsError:
        return {"error": "No credentials found for AWS."}
    except ClientError as e:
        return {"error": str(e)}
    
# Generate JWT access token  
def create_jwt_token(id, full_name, email, role):
    payload = {
        'id': id,
        'full_name': full_name,
        'email': email,
        'role': role,
        'exp': datetime.utcnow() + timedelta(days=30),  # Token expiration time
        'iat': datetime.utcnow()  # Token issuance time
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token

# User Registration View
@csrf_exempt  # This will disable CSRF protection for this view
def register_user(request):
    if request.method == 'POST':
        form_data = json.loads(request.body)  # Get the form data
        full_name = form_data['full_name']
        email = form_data['email']
        password = make_password(form_data['password'])
        role = form_data['role']
        id = uuid.uuid4()

        with connection.cursor() as cursor:
            try:
                cursor.execute(
                    "INSERT INTO users ( id, full_name, email, password, role, created_at) VALUES (%s, %s, %s, %s, %s, NOW())",
                    [id, full_name, email, password, role]
                )

                access_token = create_jwt_token(str(id), full_name, email, role)
                return JsonResponse({
                    'status': 'success', 
                    'message': 'User registered successfully',
                    'access_token': str(access_token),
                    'user': {
                        'id': id,
                        'full_name': full_name,
                        'email': email,
                        'role': role,
                        'avatar': None  # No avatar initially
                    }
                }, status=201)
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=403)


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
                "SELECT id, full_name, email, password, role, avatar FROM users WHERE email = %s",
                [email]
            )
            user = cursor.fetchone()
            print(f"User: {user}")
            if user: 
                is_valid_password = check_password(password, user[3]) # Validate hashed password
                if is_valid_password:
                    id = str(user[0]) # Convert user id to string
                    full_name = user[1]
                    email = user[2]
                    role = user[4]
                    avatar = user[5] if user[5] else ''  # Replaced with empty string if no avatar

                    access_token = create_jwt_token(id, full_name, email, role)  # Passing user_id, full_name, email, and role
                    print(f"Access Token: {access_token}")
                    return JsonResponse({
                        'status': 'success',
                        'message': 'Login Successsfull',
                        'access_token': str(access_token),
                        'user':{
                            'id': id,
                            'full_name': full_name,
                            'email': email,
                            'role': role,
                            'avatar': avatar
                        }
                    })
                else:
                    return JsonResponse({'status': 'error', 'message': 'Invalid credentials'}, status=401)
            else:
                return JsonResponse({'status': 'error', 'message': 'Invalid credentials'},  status=401)
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=403)

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

        # Get user from the database using the email
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

            return JsonResponse({
                'status': 'success', 
                'message': 'OTP sent to email.',
                'user': {
                    'id': user[0],
                    'email': email
                }
            })
        else:
            return JsonResponse({'status': 'error', 'message': 'User with this email does not exist.'}, status=401)
    else:   
        return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=403)
    

@csrf_exempt
def verify_otp_and_reset_password(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        otp = data.get('otp')
        new_password = data.get('new_password')

        if email not in otp_storage:
            return JsonResponse({'status': 'error', 'message': 'No OTP request found for this email.'})
        
        with connection.cursor() as cursor:
             cursor.execute("SELECT id, email FROM users WHERE email = %s", [email])
             user = cursor.fetchone()
        if not user:
                return JsonResponse({'status': 'error', 'message': 'User with this email does not exist.'}, status=401)

        stored_otp_info = otp_storage[email]
        stored_otp = stored_otp_info['otp']
        expires_at = stored_otp_info['expires_at']

        # Check if OTP matches and is not expired
        if otp == stored_otp and now() <= expires_at:
            # OTP is valid, update the password
            with connection.cursor() as cursor:
                hashed_password = make_password(new_password)
                user = cursor.execute("UPDATE users SET password = %s WHERE email = %s", [hashed_password, email])

            # Clear the OTP from storage after successful reset
            del otp_storage[email]

            return JsonResponse({
                'status': 'success', 
                'message': 'Password reset successfully.'
            })
        elif now() > expires_at:
            return JsonResponse({'status': 'error', 'message': 'OTP has expired.'}, status=401)
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid OTP.'}, status=401)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=403)
        


def verify_token_and_email(request):
    # Get the Authorization header from the request
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return None, JsonResponse({'status': 'error', 'message': 'Authorization header missing'}, status=401)

    # Split to get the token
    try:
        token_type, token = auth_header.split(' ')
        if token_type.lower() != 'bearer':
            return None, JsonResponse({'status': 'error', 'message': 'Invalid token type'}, status=401)

    except ValueError:
        return None, JsonResponse({'status': 'error', 'message': 'Invalid authorization header format'}, status=401)

    # Decode the token
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        token_email = decoded_token.get('email')

        if not token_email:
            return None, JsonResponse({'status': 'error', 'message': 'Email not found in token'}, status=401)

        # Fetch email from the database based on the token's email
        with connection.cursor() as cursor:
            cursor.execute("SELECT email FROM users WHERE email = %s", [token_email])
            db_email = cursor.fetchone()

        if not db_email:
            return None, JsonResponse({'status': 'error', 'message': 'User with token email does not exist.'}, status=401)

        return db_email[0], None  # Return email if successful, else None

    except jwt.ExpiredSignatureError:
        return None, JsonResponse({'status': 'error', 'message': 'Token has expired'}, status=401)
    except jwt.DecodeError:
        return None, JsonResponse({'status': 'error', 'message': 'Token is invalid'}, status=401)
    

# update user's full_name and avatar using email
@csrf_exempt
def update_profile(request):
    if request.method == 'POST':
        # Verify token and get email from the token
        token_email, error_response = verify_token_and_email(request)
        if error_response:
            return error_response

        # Get the email provided by the user in the request
        user_provided_email = request.POST.get('email')
        print(user_provided_email)
        print(token_email)

        # Match the email from the token with the user-provided email
        if token_email != user_provided_email:
            return JsonResponse({'status': 'error', 'message': 'Token email does not match the provided email.'}, status=401)

        # Extract other fields from the request
        full_name = request.POST.get('full_name')
        print(full_name)
        avatar = request.FILES.get('avatar') if 'avatar' in request.FILES else None

        # Process avatar if provided
        avatar_url = None
        if avatar:
            extension = os.path.splitext(avatar.name)[1].lower()
            if extension not in ['.png', '.jpg', '.jpeg']:
                return JsonResponse({'status': 'error', 'message': 'Only .png, .jpg, and .jpeg files are allowed.'}, status=403)

            file_name = f"avatars/{user_provided_email}_avatar{extension}"
            avatar_url = upload_to_s3(avatar, file_name)

            if "error" in avatar_url:
                return JsonResponse({"status": "error", "message": avatar_url["error"]}, status=403)

            if not avatar_url:
                return JsonResponse({'status': 'error', 'message': 'Failed to upload avatar'}, status=500)

        # Update user's full_name and avatar in the database
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, email FROM users WHERE email = %s", [user_provided_email])
            user = cursor.fetchone()

            if not user:
                return JsonResponse({'status': 'error', 'message': 'User with this email does not exist.'}, status=401)

            if avatar_url:
                cursor.execute("UPDATE users SET full_name = %s, avatar = %s WHERE email = %s", [full_name, avatar_url, user_provided_email])
            else:
                cursor.execute("UPDATE users SET full_name = %s WHERE email = %s", [full_name, user_provided_email])

        # Return success response
        return JsonResponse({
            'status': 'success',
            'message': 'Profile updated successfully.',
            'user': {
                'id': user[0],
                'email': user_provided_email,
                'full_name': full_name,
                'avatar': avatar_url if avatar_url else None
            }
        })
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=403)
