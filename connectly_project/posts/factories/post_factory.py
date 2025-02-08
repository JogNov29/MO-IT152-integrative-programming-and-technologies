from django.contrib.auth.models import User
from posts.models import Post

class PostFactory:
    @staticmethod
    def create_post(post_type, title, content='', metadata=None):
        if post_type not in dict(Post.POST_TYPES):
            raise ValueError("Invalid post type")

        # Validate type-specific requirements
        if post_type == 'image' and 'file_size' not in metadata:
            raise ValueError("Image posts require 'file_size' in metadata")
        if post_type == 'video' and 'duration' not in metadata:
            raise ValueError("Video posts require 'duration' in metadata")

        # Fetch author from metadata
        author_id = metadata.get('author_id', None)  # Get the author_id from metadata
        if not author_id:
            raise ValueError("Author is required")

        # Get the User object using the author_id
        author = User.objects.get(id=author_id)

        # Create the post with all necessary fields
        return Post.objects.create(
            title=title,
            content=content,
            post_type=post_type,
            metadata=metadata,
            author=author  # Set the author using the user instance
        )
