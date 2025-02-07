from rest_framework import serializers
from django.contrib.auth.models import User
from .models import User, Post, Comment

# **User Serializer**
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)  # Ensure password is not returned in the response

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']




# **Post Serializer**
# This serializer handles Post objects.
# It includes content, the author (linked to User), creation timestamp, and comments (related to Post).
class PostSerializer(serializers.ModelSerializer):
    # 'comments' is a reverse relation, hence StringRelatedField is used to display comments as strings.
    comments = serializers.StringRelatedField(many=True, read_only=True)

    class Meta:
        model = Post  # Using the Post model
        fields = ['id', 'content', 'author', 'created_at', 'comments']  # Fields to be included in the response

    # Optional: If you want to handle the author field more specifically, you could validate it here.
    # For example, you could ensure that the author is an active user or has specific permissions.

# **Comment Serializer**
# This serializer handles Comment objects.
# It validates that the post and author exist before creating a comment, and serializes the text of the comment.
class CommentSerializer(serializers.ModelSerializer):
    # Meta class defines which model and fields to use
    class Meta:
        model = Comment  # Using the Comment model
        fields = ['id', 'text', 'author', 'post', 'created_at']  # Fields to be included in the response

    # Validate the 'post' field to ensure the referenced post exists
    def validate_post(self, value):
        # Check if the post exists
        if not Post.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Post not found.")  # Raise an error if not found
        return value

    # Validate the 'author' field to ensure the referenced user exists
    def validate_author(self, value):
        # Check if the user exists
        if not User.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Author not found.")  # Raise an error if not found
        return value
