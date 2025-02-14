@echo off

:: Step 1: Check Python version
python --version
IF %ERRORLEVEL% NEQ 0 (
    echo "Python is not installed or not in the system PATH."
    exit /b 1
)

:: Step 2: Activate virtual environment
IF EXIST .\env\Scripts\activate (
    call .\env\Scripts\activate
    echo "Virtual environment activated."
) ELSE (
    echo "Virtual environment not found. Please create it first."
    exit /b 1
)

:: Step 3: Install dependencies
echo "Installing Django and DRF, JWT, CORS headers..."
pip install django
pip install djangorestframework
pip install djangorestframework-simplejwt
pip install django-cors-headers

:: Step 4: Run migrations
echo "Running migrations..."
python manage.py migrate

:: Step 5: Run the server
echo "Starting the development server..."
python manage.py runserver

echo "Setup Complete!"
pause
