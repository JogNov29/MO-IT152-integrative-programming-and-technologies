from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login

from .models import Post, Comment
from .serializers import UserSerializer, PostSerializer, CommentSerializer
from .permissions import IsPostAuthor


class UserLogin(APIView):
    """
    User Authentication Endpoint
    - Validates credentials 
    - Generates/returns authentication token
    - Security: Prevents login with invalid credentials
    """
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        # Authenticate user credentials
        user = authenticate(request, username=username, password=password)
        if not user:
            return Response(
                {"error": "Invalid credentials"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Log in user and generate token
        login(request, user)
        token, _ = Token.objects.get_or_create(user=user)
        
        return Response({
            "message": "Login successful", 
            "token": token.key
        }, status=status.HTTP_200_OK)


class UserCreate(APIView):
    """
    User Registration Endpoint
    - Open registration with basic validations
    - Prevents duplicate usernames/emails
    - Security: Basic input validation
    - Permissions: Allows anyone to create account
    """
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        # Validate required fields
        if not username or not password:
            return Response(
                {'error': 'Username and password are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check for existing users
        if User.objects.filter(username=username).exists():
            return Response(
                {'error': 'Username already exists.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if User.objects.filter(email=email).exists():
            return Response(
                {'error': 'Email already exists.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Create user with hashed password
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            return Response(
                UserSerializer(user).data, 
                status=status.HTTP_201_CREATED
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UserListView(APIView):
    """
    User Listing Endpoint
    - Token authentication required
    - Admin-only access
    - Security: Restricts user list to staff members
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Additional check for admin privileges
        if not request.user.is_staff:
            raise PermissionDenied('Admin access required.')
        
        # Retrieve and return user list
        users = User.objects.all()
        user_data = [
            {"id": user.id, "username": user.username, "email": user.email} 
            for user in users
        ]
        return Response(user_data, status=status.HTTP_200_OK)


class UserDetailView(APIView):
    """
    User Detail Management Endpoint
    - Token authentication required
    - Supports retrieve/update/delete
    - Security: 
      * Authenticated users can view their own details
      * Only admin can modify/delete users
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        # Retrieve specific user details
        try:
            user = User.objects.get(id=pk)
            return Response({
                'id': user.id,
                'username': user.username,
                'email': user.email
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            raise NotFound('User not found')

    def put(self, request, pk):
        # Update user (admin only)
        if not request.user.is_staff:
            raise PermissionDenied('Admin access required.')

        try:
            user = User.objects.get(id=pk)
            serializer = UserSerializer(user, data=request.data, partial=True)
            
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            raise NotFound('User not found')

    def delete(self, request, pk):
        # Delete user (admin only)
        if not request.user.is_staff:
            raise PermissionDenied('Admin access required.')

        try:
            user = User.objects.get(id=pk)
            user.delete()
            return Response(
                {"message": "User deleted successfully."}, 
                status=status.HTTP_200_OK
            )
        except User.DoesNotExist:
            raise NotFound('User not found')


class ProtectedView(APIView):
    """
    Authentication Verification Endpoint
    - Requires valid token
    - Confirms user is authenticated
    - Used for testing/verifying authentication
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Authenticated!"})


class PostListCreate(APIView):
    """
    Post Management Endpoint
    - Token authentication required
    - Supports post listing and creation
    - Security:
      * Only authenticated users can create posts
      * Validates post content
      * Automatically assigns post author
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # List all posts
        posts = Post.objects.all()
        return Response(
            PostSerializer(posts, many=True).data, 
            status=status.HTTP_200_OK
        )

    def post(self, request):
        # Create new post
        request.data['author'] = request.user.id
        content = request.data.get('content', '').strip()

        # Validate post content
        if not content:
            return Response(
                {'error': 'Post content cannot be empty.'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                serializer.data, 
                status=status.HTTP_201_CREATED
            )
        
        return Response(
            serializer.errors, 
            status=status.HTTP_400_BAD_REQUEST
        )


class PostDetailView(APIView):
    """
    Individual Post Management Endpoint
    - Token authentication required
    - Supports retrieve/update/delete
    - Security:
      * Only authenticated users can access
      * Only post author can modify/delete
      * Validates post modifications
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsPostAuthor]

    def get(self, request, pk):
        # Retrieve specific post
        try:
            post = Post.objects.get(pk=pk)
            self.check_object_permissions(request, post)
            return Response(
                {"content": post.content}, 
                status=status.HTTP_200_OK
            )
        except Post.DoesNotExist:
            raise NotFound('Post not found')

    def put(self, request, pk):
        # Update post
        try:
            post = Post.objects.get(pk=pk)
            self.check_object_permissions(request, post)

            content = request.data.get('content', '').strip()
            if not content:
                return Response(
                    {'error': 'Post content cannot be empty.'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = PostSerializer(post, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    serializer.data, 
                    status=status.HTTP_200_OK
                )
            
            return Response(
                serializer.errors, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Post.DoesNotExist:
            raise NotFound('Post not found')

    def delete(self, request, pk):
        # Delete post
        try:
            post = Post.objects.get(pk=pk)
            self.check_object_permissions(request, post)
            post.delete()
            return Response(
                {"message": "Post deleted successfully."}, 
                status=status.HTTP_200_OK
            )
        except Post.DoesNotExist:
            raise NotFound('Post not found')