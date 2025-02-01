from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
from .models import User, Post, Comment
from .serializers import UserSerializer, PostSerializer, CommentSerializer


# **User Views**

class UserListCreate(APIView):
    """
    Handles retrieving all users and creating a new user.
    """
    
    def get(self, request):
        """
        Retrieves all users from the database and returns them in JSON format.
        """
        try:
            users = User.objects.all()
            serializer = UserSerializer(users, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    def post(self, request):
        """
        Creates a new user with the provided data.
        Password hashing is not implemented here yet.
        """
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  # Save the user to the database
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# **Post Views**

class PostListCreate(APIView):
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
