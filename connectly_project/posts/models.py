from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError


# class User(models.Model):
#     username = models.CharField(max_length=100, unique=True)  # User's unique username
#     email = models.EmailField(unique=True)  # User's unique email
#     password = models.CharField(max_length=255)  # Field to store the hashed password
#     created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the user was created

#     def set_password(self, raw_password):
#         """Hash and set the password."""
#         self.password = make_password(raw_password)

#     def check_password(self, raw_password):
#         """Check if the provided password matches the stored hash."""
#         from django.contrib.auth.hashers import check_password
#         return check_password(raw_password, self.password)

#     def __str__(self):
#         return self.username



class Post(models.Model):
    POST_TYPES = (
        ('image', 'Image'),
        ('video', 'Video'),
        ('text', 'Text'),
    )
    
    # Fields
    title = models.CharField(max_length=255)  # Add title field to store the title of the post
    content = models.TextField()  # Post content
    post_type = models.CharField(max_length=50, choices=POST_TYPES)  # Post type (image, video, etc.)
    metadata = models.JSONField(null=True, blank=True)  # Store metadata in a JSON format (file_size, duration, etc.)
    created_at = models.DateTimeField(auto_now_add=True)  # Auto-filled with timestamp
    author = models.ForeignKey(User, on_delete=models.CASCADE)  # Author of the post (foreign key to User)

    def __str__(self):
        return self.title


class Comment(models.Model):
    text = models.TextField()  # The text content of the comment
    author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)  # The user who commented
    post = models.ForeignKey(Post, related_name='comments', on_delete=models.CASCADE)  # The post the comment belongs to
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the comment was created

    def __str__(self):
        return f"Comment by {self.author.username} on Post {self.post.id}"


class Like(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='likes')
    post = models.ForeignKey('Post', on_delete=models.CASCADE, related_name='likes')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Ensure a user can only like a post once
        unique_together = ('user', 'post')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} likes {self.post.title}"

    def clean(self):
        # Additional validation if needed
        if self.user == self.post.author:
            raise ValidationError("Users cannot like their own posts")