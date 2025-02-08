from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Post, Comment


class UserSerializer(serializers.ModelSerializer):
    """
    Secure User Serializer
    - Excludes sensitive information like password from the response
    - Validates unique username/email
    """
    password = serializers.CharField(
        write_only=True,  # Never returned in responses
        required=True,
        min_length=8,  # Minimum password length
        error_messages={
            'min_length': 'Password must be at least 8 characters long.'
        }
    )

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']  # Include password for creation but not for response
        extra_kwargs = {
            'username': {'validators': []},  # Remove default validators
            'email': {'required': True}
        }

    def validate_username(self, value):
        """
        Additional username validation
        - Prevent duplicate usernames
        - Enforce naming rules
        """
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists.")
        
        # Optional: Add more username validation rules
        if len(value) < 3:
            raise serializers.ValidationError("Username must be at least 3 characters long.")
        
        return value

    def validate_email(self, value):
        """
        Email validation
        - Prevent duplicate emails
        - Basic email format check
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        
        return value

    def create(self, validated_data):
        """
        Secure user creation
        - Use create_user for proper password hashing
        """
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

    def update(self, instance, validated_data):
        """
        Secure user update
        - Handle password hashing and ensure other fields are updated
        """
        password = validated_data.get('password', None)
        if password:
            instance.set_password(password)  # Hash the new password
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.save()
        return instance


class PostSerializer(serializers.ModelSerializer):
    """
    Secure Post Serializer
    - Validates post content
    - Prevents unauthorized author assignment
    """

    class Meta:
        model = Post
        fields = ['id', 'content', 'author', 'created_at']
        read_only_fields = ['author', 'created_at']

    def validate_content(self, value):
        """
        Content validation
        - Prevent empty posts
        - Optional: Add content length restrictions
        """
        if not value or value.strip() == "":
            raise serializers.ValidationError("Post content cannot be empty.")
        
        if len(value) > 1000:  # Example max length
            raise serializers.ValidationError("Post content is too long.")
        
        return value

    def create(self, validated_data):
        """
        Secure post creation
        - Enforce author as current authenticated user
        """
        # Ensure author is set from request context
        validated_data['author'] = self.context['request'].user
        return super().create(validated_data)


class CommentSerializer(serializers.ModelSerializer):
    """
    Secure Comment Serializer
    - Validates comment creation
    - Prevents unauthorized author/post assignments
    """

    class Meta:
        model = Comment
        fields = ['id', 'text', 'author', 'post', 'created_at']
        read_only_fields = ['author', 'created_at']

    def validate_text(self, value):
        """
        Comment text validation
        - Prevent empty comments
        - Optional: Add text length restrictions
        """
        if not value or value.strip() == "":
            raise serializers.ValidationError("Comment text cannot be empty.")
        
        if len(value) > 500:  # Example max length
            raise serializers.ValidationError("Comment text is too long.")
        
        return value

    def validate(self, data):
        """
        Additional validation for comment creation
        - Verify post exists
        """
        post = data.get('post')
        if not post:
            raise serializers.ValidationError("Post is required.")
        
        # Check if the post exists in the database
        try:
            post_instance = Post.objects.get(pk=post.id)
        except Post.DoesNotExist:
            raise serializers.ValidationError("The post does not exist.")
        
        return data

    def create(self, validated_data):
        """
        Secure comment creation
        - Enforce author as current authenticated user
        """
        # Ensure author is set from request context
        validated_data['author'] = self.context['request'].user
        return super().create(validated_data)
