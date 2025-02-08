from rest_framework import status
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
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
from .permissions import IsCommentAuthor
from posts.singletons.config_manager import ConfigManager
from posts.singletons.logger_singleton import LoggerSingleton
from posts.factories.post_factory import PostFactory


# CSRF Exempt Mixin
class CSRFExemptMixin(object):
    """
    Mixin to exempt a class-based view from CSRF protection.
    Any class inheriting from this mixin will have CSRF protection disabled.
    """
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(CSRFExemptMixin, self).dispatch(*args, **kwargs)

class UserLogin(CSRFExemptMixin, APIView):
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

            # Generate a token for the newly created user
            token, _ = Token.objects.get_or_create(user=user)

            # Return user data along with the generated token
            return Response({
                "message": "User created successfully",
                "token": token.key  # Token returned for immediate use
            }, status=status.HTTP_201_CREATED)
        
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
        # Validate post content
        content = request.data.get('content', '').strip()
        if not content:
            return Response(
                {'error': 'Post content cannot be empty.'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate post type (optional) if not done by the factory
        post_type = request.data.get('post_type', '')
        if post_type not in dict(Post.POST_TYPES):
            return Response(
                {'error': 'Invalid post type.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare metadata and add author_id (instead of the entire user object)
        metadata = request.data.get('metadata', {})
        metadata['author_id'] = request.user.id  # Add the user_id as author_id

        # Create the post using the factory
        try:
            post = PostFactory.create_post(post_type, request.data['title'], content, metadata)

            # Serialize and return the response
            serializer = PostSerializer(post)
            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED
            )

        except ValueError as e:
            return Response(
                {'error': str(e)},
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
        

class CommentListCreate(APIView):
    """
    Comment Management Endpoint
    - Token authentication required
    - Supports comment listing and creation
    - Security: 
        * Only authenticated users can create comments
        * Validates comment text
        * Automatically assigns comment author
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # List all comments
        comments = Comment.objects.all()
        return Response(
            CommentSerializer(comments, many=True).data,
            status=status.HTTP_200_OK
        )

    def post(self, request):
        # Create new comment
        request.data['author'] = request.user.id
        text = request.data.get('text', '').strip()
        post_id = request.data.get('post', None)

        # Validate comment text
        if not text:
            return Response(
                {'error': 'Comment text cannot be empty.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not post_id:
            return Response(
                {'error': 'A valid post ID is required to create a comment.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            post = Post.objects.get(id=post_id)
        except Post.DoesNotExist:
            return Response(
                {'error': 'The specified post does not exist.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        request.data['post'] = post.id  # Ensure post is set correctly

        # Pass the request context explicitly
        serializer = CommentSerializer(data=request.data, context={'request': request})
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

class CommentDetailView(APIView):
    """
    Individual Comment Management Endpoint
    - Token authentication required
    - Supports retrieve, update, and delete actions
    - Security: 
        * Only authenticated users can access
        * Only the comment author can update or delete their comment
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsCommentAuthor]

    def get(self, request, pk):
        # Retrieve specific comment
        try:
            comment = Comment.objects.get(pk=pk)
            self.check_object_permissions(request, comment)
            return Response(
                {"text": comment.text},
                status=status.HTTP_200_OK
            )
        except Comment.DoesNotExist:
            raise NotFound('Comment not found')

    def put(self, request, pk):
        # Update specific comment
        try:
            comment = Comment.objects.get(pk=pk)
            self.check_object_permissions(request, comment)

            text = request.data.get('text', '').strip()
            if not text:
                return Response(
                    {'error': 'Comment text cannot be empty.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = CommentSerializer(comment, data=request.data, partial=True)
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
        except Comment.DoesNotExist:
            raise NotFound('Comment not found')

    def delete(self, request, pk):
        # Delete specific comment
        try:
            comment = Comment.objects.get(pk=pk)
            self.check_object_permissions(request, comment)
            comment.delete()
            return Response(
                {"message": "Comment deleted successfully."},
                status=status.HTTP_200_OK
            )
        except Comment.DoesNotExist:
            raise NotFound('Comment not found')
       
        
class SingletonTestView(APIView):
    """
    Test Singleton behavior of the ConfigManager
    """
    def get(self, request):
        # Retrieve the DEFAULT_PAGE_SIZE from the ConfigManager Singleton
        config = ConfigManager()
        default_page_size = config.get_setting("DEFAULT_PAGE_SIZE")
        return Response({"DEFAULT_PAGE_SIZE": default_page_size})