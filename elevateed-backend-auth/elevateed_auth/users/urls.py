from django.urls import path
from . import views
from .views import register_user, login_user, forgot_password_request, verify_otp_and_reset_password

urlpatterns = [
    path('register', views.register_user, name='register'),
    path('login', views.login_user, name='login'),
    path('forgot-password', views.forgot_password_request, name='forgot-password'),
    path('reset-password', views.verify_otp_and_reset_password, name='reset-password'),
    path('update-profile', views.update_profile, name='update-profile'),
]
