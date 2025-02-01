from django.urls import path
from . import views
from .views import UserListCreate, PostListCreate, CommentListCreate

urlpatterns = [
    path('', PostListCreate.as_view(), name='post-list-create'),  # Handles both GET and POST at `/posts/`
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
]


