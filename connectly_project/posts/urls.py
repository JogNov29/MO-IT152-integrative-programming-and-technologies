from django.urls import path
from .import views
from .views import SingletonTestView
from .views import (
    UserCreate,
    UserListView,
    PostListCreate,
    CommentListCreate,
    UserLogin,
    PostDetailView,
    ProtectedView,
    UserDetailView,
    CommentDetailView,
)


urlpatterns = [
    # User Authentication and Registration
    path('login/', UserLogin.as_view(), name='user-login'),  # User Login (Generates Token)
    path('users/', UserCreate.as_view(), name='user-create'),  # User Registration (Create User)
    path('users/list/', UserListView.as_view(), name='user-list'),  # List all users (Admin only)
    path('users/<int:pk>/', UserDetailView.as_view(), name='user-detail'),  # Retrieve user details
    path('users/delete/<int:pk>/', UserDetailView.as_view(), name='delete-user'),  # Delete user (Admin only)

    # Post Management
    path('posts/', PostListCreate.as_view(), name='post-list-create'),  # List and create posts
    path('posts/<int:pk>/', PostDetailView.as_view(), name='post-detail'),  # Retrieve, update, or delete post

    # Comment Management
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),  # List and create comments
    path('comments/<int:pk>/', CommentDetailView.as_view(), name='comment-detail'),  # Retrieve, update, or delete comment

    # Protected endpoint for testing authentication
    path('protected/', ProtectedView.as_view(), name='protected-view'),
    
     # Add the SingletonTestView
    path('test-singleton/', SingletonTestView.as_view(), name='test-singleton'),
]
