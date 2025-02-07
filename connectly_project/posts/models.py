from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password


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
    content = models.TextField()  # The text content of the post
    author = models.ForeignKey(User, on_delete=models.CASCADE)  # The user who created the post
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the post was created

    def __str__(self):
        return self.content[:50]


class Comment(models.Model):
    text = models.TextField()  # The text content of the comment
    author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)  # The user who commented
    post = models.ForeignKey(Post, related_name='comments', on_delete=models.CASCADE)  # The post the comment belongs to
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the comment was created

    def __str__(self):
        return f"Comment by {self.author.username} on Post {self.post.id}"
