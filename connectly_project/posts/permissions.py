from rest_framework.permissions import BasePermission  # Import the base class for custom permissions

class IsPostAuthor(BasePermission):  # Define a new permission class called IsPostAuthor, inheriting from BasePermission
    """
    Custom permission to allow access only to the author of a post.
    """  # Docstring explaining the purpose of the permission

    def has_object_permission(self, request, view, obj):  # This method is called to check object-level permissions
        """
        Check if the requesting user is the author of the object (post).

        Args:
            request: The incoming request object.
            view: The view handling the request.
            obj: The object (post) being accessed.

        Returns:
            True if the user is the author, False otherwise.
        """
        return obj.author == request.user  # The core logic: compare the post's author to the requesting user.