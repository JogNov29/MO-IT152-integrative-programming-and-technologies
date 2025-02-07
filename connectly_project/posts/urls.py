from django.urls import path
from . import views
from .views import (
    UserListCreate, 
    PostListCreate, 
    CommentListCreate, 
    UserLogin, 
    PostDetailView, 
    ProtectedView,
    DeleteUser
)

urlpatterns = [
    path('', PostListCreate.as_view(), name='post-list-create'),
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
    path('posts/<int:pk>/', PostDetailView.as_view(), name='post-detail'),  # Add PostDetailView
    path('protected/', ProtectedView.as_view(), name='protected-view'),  # Add ProtectedView
    path('users/delete/<int:pk>/', DeleteUser.as_view(), name='delete-user'),
]


