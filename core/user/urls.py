from django.urls import path
from . import views

urlpatterns = [
    path('profile/<int:pk>/', views.UserProfileView.as_view(), name='profile-detail'),
    path('profile/update/<int:pk>/', views.UpdateProfileView.as_view(), name='profile-update'),
    path('share-link/create/', views.generate_profile_share, name='create-share-link'),
    path('share-link/verify/<uuid:token>/', views.verify_profile_share, name='verify-share-link'),
]
