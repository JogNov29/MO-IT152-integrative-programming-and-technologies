from rest_framework.permissions import BasePermission

class IsPostAuthor(BasePermission):
    """
    Custom permission to allow only the author of a post to access or modify it.
    """

    def has_object_permission(self, request, view, obj):
        """
        Check if the requesting user is the author of the post.
        
        Returns True if the user is the author, False otherwise.
        """
        return obj.author == request.user  # Allow access if the post's author matches the request user

class IsCommentAuthor(BasePermission):
    """
    Custom permission to only allow the author of a comment to edit or delete it.
    """
    def has_object_permission(self, request, view, obj):
        # Check if the request user is the author of the comment
        return obj.author == request.user
