from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter
from .views import (
    RegisterView, 
    CustomLoginView, 
    ReviewViewSet, 
    createaccount, 
    CheckProfileStatusView,
    get_profile,
    RequestResetPasswordView,
    PasswordResetConfirmView,
    LogoutView,
    generate_profile_share,
    verify_profile_share,
    submit_review,
    test_email,
    get_reviews,
    UpdateProfileView,
    UpdateSubscriptionView,
    CreatePaymentIntentView,
    StripeWebhookView
)

router = DefaultRouter()
router.register(r'reviews', ReviewViewSet)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('createaccount/', createaccount, name='create-account'),
    path('profile_status/', CheckProfileStatusView.as_view(), name='profile-status'),
    path('get_profile/', get_profile, name='get-profile'),
    path('request-reset-password/', RequestResetPasswordView.as_view(), name='request-reset-password'),
    path('reset-password-confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('api/', include(router.urls)),  # ✅ Stick to this pattern
    path('share-profile/', generate_profile_share, name='share-profile'),
    path('verify-share/<uuid:token>/', verify_profile_share, name='verify-share'),
    path('submit-review/<uuid:token>/', submit_review, name='submit-review'),
    path('test-email/', test_email, name='test-email'),
    path('get_reviews/', get_reviews, name='get_reviews'),
    path('update_profile/', UpdateProfileView.as_view(), name='update-profile'),
     # Updated subscription endpoints
    path('update-subscription/', UpdateSubscriptionView.as_view(), name='update-subscription'),
    path('create-payment-intent/', CreatePaymentIntentView.as_view(), name='create-payment-intent'),
    path('webhook/stripe/', StripeWebhookView.as_view(), name='stripe-webhook'),
]

# Add this at the end to serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
