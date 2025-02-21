from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six
from datetime import datetime, timedelta
from django.conf import settings

class CustomPasswordResetTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return six.text_type(user) + six.text_type(timestamp)
    
    #token expiration time
    def token_expired(self, token_timestamp):
        # Define your expiry time here (in seconds). E.g., set it to 10 mins (600 seconds)
        expiry_time_in_seconds = getattr(settings, 'PASSWORD_RESET_TIMEOUT', 600)
        current_timestamp = int(datetime.now().timestamp())
        return (current_timestamp - token_timestamp) > expiry_time_in_seconds


custom_password_reset_token = CustomPasswordResetTokenGenerator()