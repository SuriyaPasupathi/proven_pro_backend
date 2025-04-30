from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
import uuid
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    google_id = models.CharField(max_length=255, null=True, blank=True)
    is_google_user = models.BooleanField(default=False)
    reset_token = models.CharField(max_length=255, null=True, blank=True)
    token_created_at = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    



class UserProfile(models.Model):
    SUBSCRIPTION_CHOICES = [
        ('free', 'Free'),
        ('standard', 'Standard'),  # Changed from 'basic' to match your React component
        ('premium', 'Premium'),
    ]
    
    # User relationship
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    subscription_type = models.CharField(max_length=10, choices=SUBSCRIPTION_CHOICES, default='free')
    
    # Free tier fields
    name = models.CharField(max_length=100)
    profile_pic = models.ImageField(upload_to='profiles/', null=True, blank=True)
    job_title = models.CharField(max_length=100)
    job_specialization = models.CharField(max_length=100)
    rating = models.FloatField(default=0)  # For review ratings
    
    # URL for profile sharing
    profile_url = models.CharField(max_length=100, unique=True, blank=True, null=True)
    
    # Standard tier fields
    email = models.EmailField(blank=True)  # Additional contact email (beyond user.email)
    mobile = models.CharField(max_length=15, blank=True)
    services = models.TextField(blank=True)
    experiences = models.TextField(blank=True)
    skills = models.TextField(blank=True)
    tools = models.TextField(blank=True)
    
    # Premium tier fields
    education = models.TextField(blank=True)
    certifications = models.TextField(blank=True)
    video_intro = models.FileField(upload_to='videos/', null=True, blank=True)
    portfolio = models.TextField(blank=True)
    
    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        # Generate a unique profile URL if not provided
        if not self.profile_url:
            import uuid
            self.profile_url = str(uuid.uuid4())[:8]
        super().save(*args, **kwargs)

    def generate_share_link(self, recipient_email, expires_in_days=7):
        share = ProfileShare.objects.create(
            profile=self,
            recipient_email=recipient_email,
            expires_at=timezone.now() + timezone.timedelta(days=expires_in_days)
        )
        return share.share_token


class SocialLink(models.Model):
    """Separate model for social media links to keep the data structure clean"""
    PLATFORM_CHOICES = [
        ('linkedin', 'LinkedIn'),
        ('facebook', 'Facebook'),
        ('twitter', 'Twitter'),
        ('instagram', 'Instagram'),
        ('github', 'GitHub'),
        ('other', 'Other'),
    ]
    
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='social_links')
    platform = models.CharField(max_length=20, choices=PLATFORM_CHOICES)
    url = models.URLField()
    
    class Meta:
        unique_together = ('user_profile', 'platform')
    
    def __str__(self):
        return f"{self.user_profile.name}'s {self.get_platform_display()}"


class Review(models.Model):
    """Model for client reviews"""
    profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='client_reviews')
    reviewer_name = models.CharField(max_length=100)
    rating = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def clean(self):
        if self.rating < 1 or self.rating > 5:
            raise ValidationError('Rating must be between 1 and 5')
        
    def save(self, *args, **kwargs):
        self.full_clean()  # This will run validators and clean method
        super().save(*args, **kwargs)
        
        # Update the average rating on the profile
        profile = self.profile
        reviews = profile.client_reviews.all()
        if reviews:
            profile.rating = sum(review.rating for review in reviews) / reviews.count()
            profile.save(update_fields=['rating'])

    def generate_share_link(self, recipient_email, expires_in_days=7):
        share = ProfileShare.objects.create(
            profile=self,
            recipient_email=recipient_email,
            expires_at=timezone.now() + timezone.timedelta(days=expires_in_days)
        )
        return share.share_token


class ProfileShare(models.Model):
    profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='shares')
    share_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    recipient_email = models.EmailField()
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    def is_valid(self):
        return timezone.now() <= self.expires_at
    
    def __str__(self):
        return f"Share for {self.profile.name} - {self.recipient_email}"
    
    class Meta:
        ordering = ['-created_at']

