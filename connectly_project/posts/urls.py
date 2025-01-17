from django.urls import path
from . import views


urlpatterns = [
    path('users/', views.get_users, name='get_users'),
    path('users/create/', views.create_user, name='create_user'),
    path('', views.get_posts, name='get_posts'),
    path('create/', views.create_post, name='create_post'),
]


