from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.db import transaction
from posts.models import Profile
from datetime import datetime, timedelta
import random
import string
import os
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = "Creates profiles for all users and populates any blank details"

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Overwrite existing non-blank profile data',
        )

    def handle(self, *args, **options):
        force_update = options['force']
        
        # Locations for random assignment
        locations = [
            "New York, NY", "San Francisco, CA", "Austin, TX", "Boston, MA",
            "Seattle, WA", "Chicago, IL", "Los Angeles, CA", "Portland, OR",
            "Denver, CO", "Miami, FL", "Atlanta, GA", "Washington, DC",
            "Philadelphia, PA", "Toronto, Canada", "London, UK", "Paris, France"
        ]
        
        # Domains for websites
        website_domains = [
            "github.com", "linkedin.com", "medium.com", "twitter.com",
            "instagram.com", "facebook.com", "behance.net", "dribbble.com",
            "wordpress.com", "blogspot.com", "tumblr.com", "pinterest.com"
        ]
        
        # Bio fragments for random generation
        bio_intros = [
            "Software developer specializing in", "Passionate about", 
            "Working with", "Exploring the world of", "Experienced in",
            "Enthusiast of", "Professional focused on", "Building with"
        ]
        
        bio_technologies = [
            "Python and Django", "JavaScript and React", "mobile app development", 
            "cloud infrastructure", "machine learning", "data science", 
            "UX/UI design", "blockchain technology", "cybersecurity", 
            "IoT solutions", "game development", "web technologies"
        ]
        
        bio_extras = [
            "Always learning new things.", "Love to contribute to open-source.",
            "Enjoy solving complex problems.", "Fan of clean code and architecture.",
            "Constantly improving my skills.", "Teaching others what I know.",
            "Building side projects in my free time.", "Writing technical articles when inspired."
        ]
        
        # Count stats
        users_count = User.objects.count()
        profiles_created = 0
        profiles_updated = 0
        
        self.stdout.write(f"Found {users_count} users. Beginning profile population...")
        
        # Process all users
        with transaction.atomic():
            for user in User.objects.all():
                profile, created = Profile.objects.get_or_create(user=user)
                
                if created:
                    profiles_created += 1
                    self.stdout.write(f"Created new profile for {user.username}")
                
                # Update blank fields or force update if specified
                updated = False
                
                # Bio
                if not profile.bio or force_update:
                    bio = f"{random.choice(bio_intros)} {random.choice(bio_technologies)}. {random.choice(bio_extras)}"
                    profile.bio = bio
                    updated = True
                
                # Location
                if not profile.location or force_update:
                    profile.location = random.choice(locations)
                    updated = True
                
                # Website
                if not profile.website or force_update:
                    username_slug = user.username.lower()
                    domain = random.choice(website_domains)
                    profile.website = f"https://{domain}/{username_slug}"
                    updated = True
                
                # Birth date (between 18 and 65 years ago)
                if not profile.birth_date or force_update:
                    days_ago = random.randint(18*365, 65*365)
                    profile.birth_date = datetime.now().date() - timedelta(days=days_ago)
                    updated = True
                
                # Update profile counts
                profile.posts_count = user.post_set.count()
                profile.followers_count = profile.followers.count()
                profile.following_count = user.following.count()
                
                # Save if changes were made
                if updated or created:
                    profile.save()
                    if not created:
                        profiles_updated += 1
        
        self.stdout.write(self.style.SUCCESS(
            f"Profile population complete!\n"
            f"Created {profiles_created} new profiles\n"
            f"Updated {profiles_updated} existing profiles"
        ))