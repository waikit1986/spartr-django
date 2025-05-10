import json
import requests
from django.http import JsonResponse
from rest_framework.decorators import api_view


# Helper function to validate Apple Identity Token and Authorization Code
@api_view(['POST'])
def apple_login(request):
    # Receive the Apple identity token and authorization code from the frontend (SwiftUI app)
    data = json.loads(request.body)
    authorization_code = data.get("authorization_code")
    identity_token = data.get("identity_token")

    if not authorization_code or not identity_token:
        return JsonResponse({"error": "Missing authorization code or identity token"}, status=400)

    # Your Apple app credentials for making the token request
    client_id = 'YOUR_APPLE_CLIENT_ID'  # Replace with your actual Apple client ID
    client_secret = 'YOUR_APPLE_CLIENT_SECRET'  # Replace with your actual Apple client secret
    redirect_uri = 'YOUR_REDIRECT_URI'  # Make sure this matches the redirect URI you have set in your Apple Developer account

    # Prepare the token request
    apple_token_url = "https://appleid.apple.com/auth/token"
    params = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": authorization_code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    # Send the request to Apple to exchange the code for a token
    response = requests.post(apple_token_url, data=params)
    token_data = response.json()

    if 'access_token' in token_data:
        # If the token request is successful, get the user information
        access_token = token_data['access_token']
        user_info_url = "https://api.apple.com/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        user_response = requests.get(user_info_url, headers=headers)
        user_data = user_response.json()

        # Use the returned Apple user info (email, full name, etc.) to authenticate or create the user in your Django app
        email = user_data.get("email")
        # You can extend this to check if the user already exists and create a new one if necessary

        # For simplicity, let's assume we are creating a new user
        from django.contrib.auth.models import User
        user, created = User.objects.get_or_create(email=email)

        # If the user was created, you may want to save more details like name
        if created:
            user.first_name = user_data.get("name", {}).get("firstName", "")
            user.last_name = user_data.get("name", {}).get("lastName", "")
            user.save()

        # Create a session or JWT token for the authenticated user
        from rest_framework.authtoken.models import Token
        token, created = Token.objects.get_or_create(user=user)

        # Return the token to the frontend (SwiftUI app)
        return JsonResponse({"token": token.key}, status=200)

    else:
        return JsonResponse({"error": "Apple authentication failed"}, status=400)
