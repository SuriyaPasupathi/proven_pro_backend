from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import  permissions, status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import viewsets, permissions, status
from django.contrib.auth import get_user_model
from .serializers import RegisterSerializer, UserProfileSerializer, RequestPasswordResetSerializer, PasswordResetConfirmSerializer,ReviewSerializer
from .models import UserProfile,Review  # Assuming CustomUser is the model for your custom user
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_str
from .serializers import RegisterSerializer, UserProfileSerializer, RequestPasswordResetSerializer, PasswordResetConfirmSerializer,ReviewSerializer, ProfileShareSerializer, PublicProfileSerializer
from .models import UserProfile,Review, ProfileShare  # Assuming CustomUser is the model for your custom user
from django.conf import settings
from django.utils import timezone
import uuid
from rest_framework.parsers import MultiPartParser, FormParser
from django.core.mail import EmailMultiAlternatives
import stripe
from django.http import JsonResponse
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail

stripe.api_key = settings.STRIPE_SECRET_KEY

User = get_user_model()

# ✅ Register View
class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            refresh = RefreshToken.for_user(user)
            access = refresh.access_token

            return Response({
                "message": "Account created successfully!",
                "refresh": str(refresh),
                "access": str(access)
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# ✅ Login View (Custom response with tokens)
class CustomLoginView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        user = User.objects.filter(email=email).first()

        if user and user.check_password(password):
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "Login successful!",
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                }
            }, status=status.HTTP_200_OK)

        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def createaccount(request):
    user = request.user
    data = request.data

    profile, created = UserProfile.objects.get_or_create(user=user)
    subscription_type = data.get('subscription_type', 'free')

    profile.subscription_type = subscription_type
    profile.name = data.get('name', '')
    profile.job_title = data.get('job_title', '')
    profile.job_specialization = data.get('job_specialization', '')

    if request.FILES.get('profile_pic'):
        profile.profile_pic = request.FILES['profile_pic']

    if subscription_type == 'standard' or subscription_type == 'premium':
        profile.email = data.get('email', '')
        profile.mobile = data.get('mobile', '')
        profile.services = data.get('services', '')
        profile.experiences = data.get('experiences', '')
        profile.skills = data.get('skills', '')
        profile.tools = data.get('tools', '')

    if subscription_type == 'premium':
        profile.education = data.get('education', '')
        profile.certifications = data.get('certifications', '')
        profile.portfolio = data.get('portfolio', '')
        if request.FILES.get('video_intro'):
            profile.video_intro = request.FILES['video_intro']

    profile.save()
    serializer = UserProfileSerializer(profile)
    return Response(serializer.data)


# class UserProfileViewSet(viewsets.ModelViewSet):
#     queryset = UserProfile.objects.all()
#     serializer_class = UserProfileSerializer
#     permission_classes = [permissions.IsAuthenticated]
    
#     def get_queryset(self):
#         queryset = super().get_queryset()

#         if not self.request.user.is_staff:
#             queryset = queryset.filter(user=self.request.user)

#         subscription = self.request.query_params.get('subscription')
#         if subscription:
#             queryset = queryset.filter(subscription_type=subscription)

#         return queryset

    
#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)
    
    # @action(detail=True, methods=['post'])
    # def upgrade_subscription(self, request, pk=None):
    #     profile = self.get_object()
    #     subscription_type = request.data.get('subscription_type')
        
    #     if subscription_type not in [choice[0] for choice in UserProfile.SUBSCRIPTION_CHOICES]:
    #         return Response(
    #             {'error': 'Invalid subscription type'}, 
    #             status=status.HTTP_400_BAD_REQUEST
    #         )
        
    #     profile.subscription_type = subscription_type
    #     profile.save()
    #     return Response({'status': 'subscription updated'})


class ReviewViewSet(viewsets.ModelViewSet):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    
    def perform_create(self, serializer):
        profile_id = self.request.data.get('profile_id')
        try:
            profile = UserProfile.objects.get(id=profile_id)
            serializer.save(profile=profile)
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'Profile not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
    
class CheckProfileStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        try:
            profile = UserProfile.objects.get(user=user)
            serializer = UserProfileSerializer(profile, context={"request": request})
            return Response({
                "has_profile": True,
                # "profile": serializer.data
            }, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response({"has_profile": False}, status=status.HTTP_200_OK)  



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile(request):
    try:
        print(f"Request User: {request.user}")  # Debug print to see if user is authenticated
        profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        return Response({'detail': 'Profile does not exist.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    serializer = UserProfileSerializer(profile)
    return Response(serializer.data, status=status.HTTP_200_OK)


class RequestResetPasswordView(APIView):
    def post(self, request):
        serializer = RequestPasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            reset_link = f"{settings.FRONTEND_URL}/ResetPassword?uid={uid}&token={token}"

            # HTML email content
            html_message = f"""
            <html>
                <body>
                    <h2>Password Reset Request</h2>
                    <p>Hello,</p>
                    <p>You've requested to reset your password. Click the link below to reset it:</p>
                    <p><a href="{reset_link}">Reset Your Password</a></p>
                    <p>Or copy and paste this link in your browser:</p>
                    <p>{reset_link}</p>
                    <p>If you didn't request this, please ignore this email.</p>
                    <p>This link will expire soon for security reasons.</p>
                    <br>
                    <p>Best regards,<br>The Team</p>
                </body>
            </html>
            """

            # Plain text version
            text_message = f"""
            Password Reset Request

            Hello,

            You've requested to reset your password. Please visit this link to reset it:
            {reset_link}

            If you didn't request this, please ignore this email.
            This link will expire soon for security reasons.

            Best regards,
            The Team
            """

            try:
                from django.core.mail import EmailMultiAlternatives
                
                subject = "Reset Your Password"
                email_message = EmailMultiAlternatives(
                    subject=subject,
                    body=text_message,
                    from_email=settings.EMAIL_HOST_USER,
                    to=[email],
                )
                email_message.attach_alternative(html_message, "text/html")
                email_message.send(fail_silently=False)

                return Response({
                    "message": "Password reset link sent to your email.",
                    "success": True
                })

            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Password reset email failed: {str(e)}")
                return Response({
                    "error": "Failed to send password reset email. Please try again later.",
                    "details": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)


class PasswordResetConfirmView(APIView):
    """
    Confirm password reset with token and set new password
    """
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        uid = serializer.validated_data['uid']
        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']

        try:
            # Decode the user ID
            uid = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uid)

            # Check if the token is valid
            if default_token_generator.check_token(user, token):
                user.set_password(new_password)
                user.save()
                return Response({"message": "Password reset successful."})
            else:
                return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
                
        except User.DoesNotExist:
            return Response({"error": "Invalid user ID."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout successful."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_profile_share(request):
    recipient_email = request.data.get('email')
    if not recipient_email:
        return Response(
            {'error': 'Email is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        profile = request.user.profile
        
        # Create share with 7 days expiration
        share = ProfileShare.objects.create(
            profile=profile,
            recipient_email=recipient_email,
            expires_at=timezone.now() + timezone.timedelta(days=7)
        )
        
        verification_url = f"{settings.FRONTEND_URL}/verify-profile/{share.share_token}"
        
        # HTML email content
        html_message = f"""
        <html>
            <body>
                <h2>Profile Review Request</h2>
                <p>Hello,</p>
                <p>You've been invited to review {profile.name}'s professional profile.</p>
                <p><a href="{verification_url}">Click here to view and leave a review</a></p>
                <p>Or copy and paste this link in your browser:</p>
                <p>{verification_url}</p>
                <p>Note: This link will expire in 7 days.</p>
                <br>
                <p>Best regards,<br>The Team</p>
            </body>
        </html>
        """
        
        # Plain text email content
        text_message = f"""
        Profile Review Request

        Hello,

        You've been invited to review {profile.name}'s professional profile.

        Please visit this link to view and leave a review:
        {verification_url}

        Note: This link will expire in 7 days.

        Best regards,
        The Team
        """
        
        try:
     
            
            subject = f"Profile Review Request from {profile.name}"
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_message,
                from_email=settings.EMAIL_HOST_USER,
                to=[recipient_email],
            )
            email.attach_alternative(html_message, "text/html")
            email.send(fail_silently=False)
            
            return Response({
                'message': 'Share link sent successfully',
                'share_token': str(share.share_token),
                'verification_url': verification_url
            })
            
        except Exception as e:
            # Log the error for debugging
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Email sending failed: {str(e)}")
            
            # Still return success since the share link was created
            return Response({
                'message': 'Share link created but email sending failed. Please share the link manually.',
                'share_token': str(share.share_token),
                'verification_url': verification_url
            }, status=status.HTTP_201_CREATED)
            
    except UserProfile.DoesNotExist:
        return Response(
            {'error': 'Profile not found'},
            status=status.HTTP_404_NOT_FOUND
        )

@api_view(['GET'])
def verify_profile_share(request, token):
    try:
        # Convert string token to UUID if needed
        if isinstance(token, str):
            token = uuid.UUID(token)
            
        share = ProfileShare.objects.select_related('profile').get(share_token=token)
        
        # Check if share is expired
        if timezone.now() > share.expires_at:
            return Response(
                {'error': 'This link has expired'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Serialize the profile data
        serializer = PublicProfileSerializer(share.profile)
        return Response({
            'profile': serializer.data,
            'share_token': str(share.share_token)
        })
        
    except (ProfileShare.DoesNotExist, ValueError, TypeError):
        return Response(
            {'error': 'Invalid share token'},
            status=status.HTTP_404_NOT_FOUND
        )

@api_view(['POST'])
def submit_review(request, token):
    try:
        # Get the share object and validate it
        share = ProfileShare.objects.get(share_token=token)
        if not share.is_valid():
            return Response({'error': 'Link expired or invalid'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create review data using the profile from the share object
        review_data = {
            'profile': share.profile.id,  # Get profile ID from the share object
            'reviewer_name': request.data.get('reviewer_name'),
            'rating': request.data.get('rating'),
            'comment': request.data.get('comment')
        }
        
        # Validate that required fields are present
        if not all([review_data['reviewer_name'], review_data['rating'], review_data['comment']]):
            return Response({
                'error': 'reviewer_name, rating, and comment are required fields'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = ReviewSerializer(data=review_data)
        if serializer.is_valid():
            review = serializer.save()
            return Response({
                'message': 'Review submitted successfully',
                'review': ReviewSerializer(review).data
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    except ProfileShare.DoesNotExist:
        return Response({
            'error': 'Invalid share token'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error submitting review: {str(e)}")
        return Response({
            'error': 'An error occurred while submitting the review'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def test_email(request):
    email = request.data.get('email', '')
    
    if not email:
        return Response(
            {'error': 'Email is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Validate email format
        validate_email(email)
        
        # Attempt to send email
        result = send_mail(
            subject='Test Email',
            message='This is a test email.',
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[email],
            fail_silently=False,
        )
        
        if result == 0:
            raise Exception("Failed to send email")
            
        return Response({'message': 'Test email sent successfully'})
    except ValidationError:
        return Response(
            {'error': 'Invalid email format'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_reviews(request):
    # Get the profile associated with the current user
    profile = request.user.profile
    
    # Get all reviews for this profile
    reviews = Review.objects.filter(profile=profile).order_by('-created_at')
    
    # Serialize and return the reviews
    serializer = ReviewSerializer(reviews, many=True)
    return Response(serializer.data)

class UpdateProfileView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def put(self, request, *args, **kwargs):
        user = request.user  # Get the logged-in user
        profile = UserProfile.objects.get(user=user)
        
        serializer = UserProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

class UpdateSubscriptionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Update user's subscription type and check if they have an existing profile
        """
        subscription_type = request.data.get('subscription_type')
        
        if subscription_type not in ['free', 'standard', 'premium']:
            return Response(
                {'message': 'Invalid subscription type'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Try to get existing profile
            profile = UserProfile.objects.get(user=request.user)
            profile.subscription_type = subscription_type
            profile.save()
            
            return Response({
                'message': 'Subscription updated successfully',
                'has_profile': True
            })
            
        except UserProfile.DoesNotExist:
            # If no profile exists, just return has_profile as False
            return Response({
                'message': 'Ready to create profile',
                'has_profile': False
            })


class CreatePaymentIntentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            subscription_type = request.data.get('subscription_type')
            
            # Get price based on subscription type
            price_id = settings.STRIPE_PRICE_IDS.get(subscription_type)
            print("aslkjdnlkjansdlknasd",price_id)
            if not price_id:
                return Response(
                    {'error': 'Invalid subscription type'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                # Verify the price exists in Stripe
                stripe.Price.retrieve(price_id)
            except stripe.error.InvalidRequestError:
                return Response(
                    {'error': f'Invalid price ID configuration for {subscription_type} subscription'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Create Stripe Checkout Session
            checkout_session = stripe.checkout.Session.create(
                customer_email=request.user.email,
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='payment',
                success_url=f'{settings.FRONTEND_URL}/payment-success?session_id={{CHECKOUT_SESSION_ID}}',
                cancel_url=f'{settings.FRONTEND_URL}/subscription',
                metadata={
                    'user_id': request.user.id,
                    'subscription_type': subscription_type
                }
            )
            
            return Response({
                'sessionId': checkout_session.id,
                'publicKey': settings.STRIPE_PUBLISHABLE_KEY
            })
            
        except stripe.error.StripeError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            return Response(
                {'error': 'An unexpected error occurred'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class StripeWebhookView(APIView):
    authentication_classes = []  # No authentication for webhooks
    permission_classes = []      # No permissions for webhooks

    def post(self, request):
        payload = request.body
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
            )

            if event['type'] == 'checkout.session.completed':
                session = event['data']['object']
                
                # Get user and subscription details from metadata
                user_id = session['metadata']['user_id']
                subscription_type = session['metadata']['subscription_type']
                
                # Update user's profile with new subscription
                try:
                    profile = UserProfile.objects.get(user_id=user_id)
                    profile.subscription_type = subscription_type
                    profile.subscription_active = True
                    profile.save()
                except UserProfile.DoesNotExist:
                    # Create new profile if doesn't exist
                    UserProfile.objects.create(
                        user_id=user_id,
                        subscription_type=subscription_type,
                        subscription_active=True
                    )

            return Response({'status': 'success'})

        except ValueError:
            return Response(
                {'error': 'Invalid payload'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except stripe.error.SignatureVerificationError:
            return Response(
                {'error': 'Invalid signature'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
