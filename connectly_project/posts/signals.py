from django.db.models.signals import post_save
from django.dispatch import receiver
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import User
import random
import string

@receiver(post_save, sender=SocialAccount)
def create_user_profile(sender, instance, created, **kwargs):
    """
    When a new Google account is connected, make sure the user has
    a valid username if they don't already have one
    """
    if created and instance.provider == 'google':
        user = instance.user
        
        # If the user doesn't have a username (or it's their email),
        # generate one based on their Google info
        if not user.username or '@' in user.username:
            # Try to use their first name + last name
            if user.first_name and user.last_name:
                username_base = f"{user.first_name.lower()}_{user.last_name.lower()}"
            else:
                # Or use the part of their email before the @
                email_name = user.email.split('@')[0]
                username_base = email_name
                
            # Make it unique if needed
            username = username_base
            counter = 1
            
            # Keep trying until we find a unique username
            while User.objects.filter(username=username).exists():
                username = f"{username_base}{counter}"
                counter += 1
                
            user.username = username
            user.save()