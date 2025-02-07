from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import PermissionDenied
from .permissions import IsPostAuthor
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
from .models import User, Post, Comment
from .serializers import UserSerializer, PostSerializer, CommentSerializer

# User List Creation
class UserListCreate(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated
    
    def post(self, request):
        # Check if the user is authenticated
        if not request.user.is_authenticated:
            return Response(
                {'error': 'You must be logged in to create a new user.'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if the user is an admin
        if not request.user.is_staff:
            raise PermissionDenied("You do not have permission to create users.")
        
        # Get the user data from the request
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        # Ensure required fields are provided
        if not username or not password:
            return Response(
                {'error': 'Username and password are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if the username already exists
        if User.objects.filter(username=username).exists():
            return Response(
                {'error': 'Username already exists.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if the email already exists
        if User.objects.filter(email=email).exists():
            return Response(
                {'error': 'Email already exists.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Create the new user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            # Serialize the user object to return in the response
            serializer = UserSerializer(user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            # Log the error and return the response with detailed information
            print(f"Error creating user: {str(e)}")
            return Response(
                {'error': f'Error: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# **Post Views**
@method_decorator(csrf_exempt, name='dispatch')
class PostListCreate(APIView):
    permission_classes = [IsAuthenticated]
    """
    Handles retrieving all posts and creating a new post.
    """
    
    def get(self, request):
        """
        Retrieves all posts from the database and returns them in JSON format.
        """
        try:
            posts = Post.objects.all()
            serializer = PostSerializer(posts, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    def post(self, request):
        """
        Creates a new post with the provided data, associating it with an existing user (author).
        """
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            try:
                # Check if the author exists before creating the post
                author = User.objects.get(id=request.data['author'])
                serializer.save(author=author)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except User.DoesNotExist:
                return JsonResponse({'error': 'Author not found'}, status=404)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# **Comment Views**
@method_decorator(csrf_exempt, name='dispatch')
class CommentListCreate(APIView):
    """
    Handles retrieving all comments and creating a new comment.
    """
    
    def get(self, request):
        """
        Retrieves all comments from the database and returns them in JSON format.
        """
        try:
            comments = Comment.objects.all()
            serializer = CommentSerializer(comments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    def post(self, request):
        """
        Creates a new comment with the provided data, associating it with an existing post and user.
        """
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            try:
                # Check if the associated post exists before creating the comment
                post = Post.objects.get(id=request.data['post'])
                serializer.save(post=post)  # Save comment with the associated post
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except Post.DoesNotExist:
                return JsonResponse({'error': 'Post not found'}, status=404)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@method_decorator(csrf_exempt, name='dispatch')
class UserLogin(APIView):
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
            

class PostDetailView(APIView):
    permission_classes = [IsAuthenticated, IsPostAuthor]  # Apply both permissions

    def get(self, request, pk):
        post = Post.objects.get(pk=pk)  # Get the post
        self.check_object_permissions(request, post)  # Check object-level permissions
        return Response({"content": post.content})  # Return the post content
    
@method_decorator(csrf_exempt, name='dispatch')
class ProtectedView(APIView):  # Example protected view
    authentication_classes = [TokenAuthentication]  # Use token authentication
    permission_classes = [IsAuthenticated]  # Must be authenticated

    def get(self, request):
        return Response({"message": "Authenticated!"})
    
@method_decorator(csrf_exempt, name='dispatch')
class DeleteUser(APIView):
    def delete(self, request, pk):
        try:
            user = User.objects.get(id=pk)  # Get user by ID
            user.delete()  # Delete the user
            return Response({"message": "User deleted successfully."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)