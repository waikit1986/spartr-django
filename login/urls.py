from django.urls import path
from . import views

urlpatterns = [
    path('apple_login/', views.apple_login, name='apple_login'),
]
