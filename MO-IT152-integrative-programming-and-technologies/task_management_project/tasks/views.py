import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import User, Task


# Create your views here.
def get_users(request):
    users = list(User.objects.values('id', 'username', 'email', 'created_at'))
    return JsonResponse(users, safe=False)
@csrf_exempt
def create_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        user = User.objects.create(username=data['username'], email=data['email'])
        return JsonResponse({'id': user.id, 'message': 'User created successfully'}, status=201)
def get_tasks(request):
    tasks = list(Task.objects.values('id', 'title', 'description', 'is_completed', 'user', 'created_at'))
    return JsonResponse(tasks, safe=False)
@csrf_exempt
def create_task(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        user = User.objects.get(id=data['user'])  # Ensure the user exists
        task = Task.objects.create(title=data['title'], description=data.get('description', ''), user=user)
        return JsonResponse({'id': task.id, 'message': 'Task created successfully'}, status=201)
