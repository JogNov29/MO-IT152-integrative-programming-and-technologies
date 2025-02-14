from posts.singletons.logger_singleton import LoggerSingleton
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings

class LoggingMiddleware:
    """
    A middleware that logs every request and response.
    It logs the request method, path, user, and response status code.
    """
    def __init__(self, get_response):
        # The get_response function is provided by Django to call the next middleware
        self.get_response = get_response
        self.logger = LoggerSingleton().get_logger()

    def __call__(self, request):
        # Log the incoming request
        self.logger.info(f"Request: {request.method} {request.path} - User: {request.user}")

        # Get the response from the next middleware/view
        response = self.get_response(request)

        # Log the outgoing response status code
        self.logger.info(f"Response: {response.status_code} for {request.method} {request.path}")

        return response


class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            jwt_auth = JWTAuthentication()
            user_auth_tuple = jwt_auth.authenticate(request)
            if user_auth_tuple is not None:
                request.user, request.auth = user_auth_tuple
        except:
            pass

        response = self.get_response(request)
        return response
