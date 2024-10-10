from django.contrib.auth import login, logout
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .forms import CustomUserCreationForm
from .models import CustomUser
import random
from threading import Thread  # Import threading to send email in a separate thread
from django.contrib.auth.models import User

# Function to generate a 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Function to send email in a separate thread
def send_otp_email(email, otp):
    send_mail(
        'Your OTP Code',
        f'Your OTP code is {otp}',
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Get data from request
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')

        # Check if password and confirm_password match
        if password != confirm_password:
            return Response({"error": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

        # Use the CustomUserCreationForm for validation
        form = CustomUserCreationForm(request.data)

        if form.is_valid():
            otp = generate_otp()
            temp_data = {
                'email': email,
                'username': username,
                'password': password,
                'otp': otp,
            }
            request.session['signup_data'] = temp_data

            # Send OTP email in a separate thread
            email_thread = Thread(target=send_otp_email, args=(email, otp))
            email_thread.start()

            return Response({
                "message": "Account created! Please check your email to verify your OTP.",
                "user": {
                    "username": username,
                    "email": email
                }
            }, status=status.HTTP_201_CREATED)

        return Response({"error": form.errors}, status=status.HTTP_400_BAD_REQUEST)

class VerifyOtpView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp_input = request.data.get('otp')
        temp_data = request.session.get('signup_data')

        if not temp_data:
            return Response({"error": "No OTP session found. Please register again."}, status=status.HTTP_400_BAD_REQUEST)

        email = temp_data.get('email')
        username = temp_data.get('username')
        password = temp_data.get('password')
        otp = temp_data.get('otp')

        if otp_input and otp == otp_input:
            user = CustomUser(username=username, email=email)
            user.set_password(password)
            user.is_active = True
            user.is_verified = True  # Mark user as verified
            user.save()

            del request.session['signup_data']

            return Response({"message": "Email verified successfully! You can now log in."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid OTP. Please try again."}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)

            if not user.is_active:
                return Response({"error": "User is inactive."}, status=status.HTTP_403_FORBIDDEN)

            if not user.is_verified:
                return Response({"error": "Please verify your email before logging in."}, status=status.HTTP_400_BAD_REQUEST)

            # Check password
            if user.check_password(password):
                login(request, user)  # Log the user in
                return Response({"message": "Login successful!"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid password."}, status=status.HTTP_401_UNAUTHORIZED)

        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        logout(request)
        return Response({"message": "Successfully logged out."}, status=status.HTTP_205_RESET_CONTENT)

# HomeView to retrieve CustomUser data excluding sensitive information
class HomeView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        # Get the logged-in user
        logged_in_user = request.user

        # Retrieve all users except the logged-in user, excluding sensitive fields
        users = CustomUser.objects.exclude(id=logged_in_user.id).values('id', 'username', 'email', 'is_active')

        response_data = {
            'users': list(users),  # Convert queryset to list for JSON serialization
        }

        return Response(response_data, status=status.HTTP_200_OK)
