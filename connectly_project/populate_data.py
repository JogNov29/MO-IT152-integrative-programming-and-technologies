"""
Connectly Data Population Script

This script creates test data for the Connectly application including:
- Users
- Profiles (automatically created via signals)
- Posts (text, image, video)
- Comments
- Likes
- Follow relationships

Usage:
- Place this script in the root directory of your Django project
- Run it with: python manage.py shell < populate_data.py
"""

import os
import sys
import random
import string
import datetime
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.models import User
from django.core.management import call_command
from posts.models import Profile, Post, Comment, Like
from faker import Faker

# Initialize Faker
fake = Faker()

# Configuration
NUM_USERS = 100
MAX_POSTS_PER_USER = 20
MAX_COMMENTS_PER_POST = 15
MAX_LIKES_PER_POST = 30
MAX_FOLLOWS_PER_USER = 20

print("Starting Connectly test data population...")

# Create users with profiles (profiles auto-created via signals)
print(f"Creating {NUM_USERS} users and profiles...")
users = []

with transaction.atomic():
    # First check if we already have users to avoid duplicates
    existing_count = User.objects.count()
    if existing_count > 5:  # Assuming there might be some existing test users or admin accounts
        print(f"Found {existing_count} existing users. Skipping user creation.")
    else:
        for i in range(NUM_USERS):
            username = f"user_{i+1}"
            email = f"user{i+1}@example.com"
            
            # Skip if user already exists
            if User.objects.filter(username=username).exists():
                continue
                
            # Create user with profile (profile created via signal)
            user = User.objects.create_user(
                username=username,
                email=email,
                password="password123",
                first_name=fake.first_name(),
                last_name=fake.last_name()
            )
            users.append(user)
            
            if (i+1) % 10 == 0:
                print(f"Created {i+1} users")

    # Make sure we populate the profile data for all users
    call_command('populate_profiles', force=True)

# Get all users if we didn't create new ones
if not users:
    users = list(User.objects.all())
    print(f"Using {len(users)} existing users")

# Create posts
print(f"\nCreating posts (up to {MAX_POSTS_PER_USER} per user)...")
posts = []

post_types = ['text', 'image', 'video']
image_formats = ['jpg', 'png', 'gif']
video_formats = ['mp4', 'mov', 'avi']

with transaction.atomic():
    post_count = 0
    for user in users:
        # Random number of posts for this user
        num_posts = random.randint(1, MAX_POSTS_PER_USER)
        
        for _ in range(num_posts):
            # Pick a random post type
            post_type = random.choice(post_types)
            
            # Generate metadata based on post type
            metadata = {
                'author_id': user.id,
                'tags': random.sample(['tech', 'travel', 'food', 'sports', 'music', 'art', 'fashion', 'news'], k=random.randint(0, 3))
            }
            
            if post_type == 'image':
                metadata.update({
                    'width': random.randint(800, 1600),
                    'height': random.randint(600, 900),
                    'format': random.choice(image_formats),
                    'file_size': random.randint(100000, 5000000)
                })
                content = f"https://picsum.photos/id/{random.randint(1, 1000)}/{metadata['width']}/{metadata['height']}"
                
            elif post_type == 'video':
                duration = random.randint(10, 180)
                metadata.update({
                    'duration': duration,
                    'format': random.choice(video_formats),
                    'resolution': random.choice(['720p', '1080p', '4K']),
                    'file_size': random.randint(1000000, 100000000)
                })
                content = f"https://example.com/videos/sample{random.randint(1, 100)}.{metadata['format']}"
                
            else:  # text post
                content = fake.paragraph(nb_sentences=random.randint(3, 8))
                
            # Create post title
            title = fake.sentence(nb_words=random.randint(4, 8)).rstrip('.')
            
            # Created date (between 90 days ago and now)
            created_days_ago = random.randint(0, 90)
            created_at = timezone.now() - datetime.timedelta(days=created_days_ago)
            
            post = Post.objects.create(
                title=title,
                content=content,
                post_type=post_type,
                metadata=metadata,
                author=user,
            )
            
            # Set created_at manually (backdating)
            post.created_at = created_at
            post.save(update_fields=['created_at'])
            
            posts.append(post)
            post_count += 1
            
            if post_count % 50 == 0:
                print(f"Created {post_count} posts")

print(f"Created a total of {len(posts)} posts")

# Create comments
print(f"\nCreating comments (up to {MAX_COMMENTS_PER_POST} per post)...")
comments = []

with transaction.atomic():
    comment_count = 0
    for post in posts:
        # Random number of comments for this post
        num_comments = random.randint(0, MAX_COMMENTS_PER_POST)
        
        for _ in range(num_comments):
            # Random user comments (but not the author)
            potential_commenters = [u for u in users if u != post.author]
            author = random.choice(potential_commenters)
            
            # Created date (between post date and now)
            post_age = (timezone.now() - post.created_at).days
            if post_age > 0:
                comment_days_ago = random.randint(0, post_age)
            else:
                comment_days_ago = 0
            created_at = timezone.now() - datetime.timedelta(days=comment_days_ago)
            
            # Create comment
            text = fake.paragraph(nb_sentences=random.randint(1, 3))
            comment = Comment.objects.create(
                text=text,
                author=author,
                post=post
            )
            
            # Set created_at manually (backdating)
            comment.created_at = created_at
            comment.save(update_fields=['created_at'])
            
            comments.append(comment)
            comment_count += 1
            
            if comment_count % 100 == 0:
                print(f"Created {comment_count} comments")

print(f"Created a total of {len(comments)} comments")

# Create likes
print(f"\nCreating likes (up to {MAX_LIKES_PER_POST} per post)...")

with transaction.atomic():
    like_count = 0
    for post in posts:
        # Random number of likes for this post
        num_likes = random.randint(0, min(MAX_LIKES_PER_POST, len(users) - 1))
        
        # Random users like the post (but not the author)
        potential_likers = [u for u in users if u != post.author]
        likers = random.sample(potential_likers, num_likes)
        
        for user in likers:
            # Skip if like already exists
            if Like.objects.filter(user=user, post=post).exists():
                continue
                
            # Created date (between post date and now)
            post_age = (timezone.now() - post.created_at).days
            if post_age > 0:
                like_days_ago = random.randint(0, post_age)
            else:
                like_days_ago = 0
            created_at = timezone.now() - datetime.timedelta(days=like_days_ago)
            
            # Create like
            like = Like.objects.create(
                user=user,
                post=post
            )
            
            # Set created_at manually (backdating)
            like.created_at = created_at
            like.save(update_fields=['created_at'])
            
            like_count += 1
            
            if like_count % 100 == 0:
                print(f"Created {like_count} likes")

print(f"Created a total of {like_count} likes")

# Create follow relationships
print(f"\nCreating follow relationships (up to {MAX_FOLLOWS_PER_USER} follows per user)...")

with transaction.atomic():
    follow_count = 0
    for user in users:
        # Random number of users to follow
        num_follows = random.randint(0, min(MAX_FOLLOWS_PER_USER, len(users) - 1))
        
        # Random users to follow (but not self)
        potential_follows = [u for u in users if u != user]
        follows = random.sample(potential_follows, num_follows)
        
        for follow_user in follows:
            # Add the follow relationship
            profile = Profile.objects.get(user=follow_user)
            profile.followers.add(user)
            
            follow_count += 1
            
        if (user.id % 10) == 0:
            print(f"Processed follow relationships for {user.id} users")
    
    # Update all profile counts
    for user in users:
        profile = Profile.objects.get(user=user)
        profile.update_counts()

print(f"Created a total of {follow_count} follow relationships")

# Final summary
user_count = User.objects.count()
profile_count = Profile.objects.count()
post_count = Post.objects.count()
comment_count = Comment.objects.count()
like_count = Like.objects.count()

print("\n=== POPULATION SUMMARY ===")
print(f"Users: {user_count}")
print(f"Profiles: {profile_count}")
print(f"Posts: {post_count}")
print(f"Comments: {comment_count}")
print(f"Likes: {like_count}")
print(f"Follows: {follow_count}")
print("=========================")
print("\nData population complete!")