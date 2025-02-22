from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from rest_framework_simplejwt.tokens import RefreshToken
import random
import string

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        """
        Called before the social login is committed to the database
        """
        # If the user is new (hasn't logged in before)
        if not sociallogin.is_existing:
            # The user will be created by allauth automatically
            # We can customize username generation here if needed
            user = sociallogin.user
            
            # If username is not set, generate one from email
            if not user.username:
                email_name = user.email.split('@')[0]
                random_string = ''.join(random.choices(string.digits, k=4))
                user.username = f"{email_name}_{random_string}"
                
            # Any other customizations can go here
            
        # Let allauth handle everything else

    def save_user(self, request, sociallogin, form=None):
        """
        Custom user creation
        """
        user = super().save_user(request, sociallogin, form)
        return user