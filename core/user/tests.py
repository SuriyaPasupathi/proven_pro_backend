from django.test import TestCase
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.utils import IntegrityError
from rest_framework.test import APIClient
from rest_framework import status
from user.models import UserProfile, SocialLink, Review, ProfileShare
import datetime

User = get_user_model()

class CustomUserTests(TestCase):
    def setUp(self):
        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password': 'testpass123'
        }

    def test_create_user(self):
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.email, self.user_data['email'])
        self.assertEqual(user.username, self.user_data['username'])
        self.assertTrue(user.check_password(self.user_data['password']))
        self.assertFalse(user.is_google_user)

    def test_create_google_user(self):
        user = User.objects.create_user(
            email='google@example.com',
            username='googleuser',
            password='testpass123',
            is_google_user=True,
            google_id='123456789'
        )
        self.assertTrue(user.is_google_user)
        self.assertEqual(user.google_id, '123456789')

    def test_reset_token(self):
        user = User.objects.create_user(**self.user_data)
        user.reset_token = 'test_token'
        user.save()
        self.assertEqual(user.reset_token, 'test_token')


class UserProfileTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123'
        )
        self.profile_data = {
            'user': self.user,
            'name': 'Test User',
            'job_title': 'Software Developer',
            'job_specialization': 'Backend Development',
            'subscription_type': 'free'
        }

    def test_create_profile(self):
        profile = UserProfile.objects.create(**self.profile_data)
        self.assertEqual(profile.name, self.profile_data['name'])
        self.assertEqual(profile.job_title, self.profile_data['job_title'])
        self.assertTrue(profile.profile_url)
        self.assertEqual(profile.rating, 0)

    def test_profile_url_generation(self):
        profile = UserProfile.objects.create(**self.profile_data)
        self.assertIsNotNone(profile.profile_url)
        self.assertEqual(len(profile.profile_url), 8)

    def test_subscription_types(self):
        profile = UserProfile.objects.create(**self.profile_data)
        
        # Test free subscription
        self.assertEqual(profile.subscription_type, 'free')

        # Test standard subscription
        profile.subscription_type = 'standard'
        profile.save()
        self.assertEqual(profile.subscription_type, 'standard')

        # Test premium subscription
        profile.subscription_type = 'premium'
        profile.save()
        self.assertEqual(profile.subscription_type, 'premium')


class SocialLinkTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123'
        )
        self.profile = UserProfile.objects.create(
            user=self.user,
            name='Test User',
            job_title='Developer',
            job_specialization='Web'
        )

    def test_create_social_link(self):
        social_link = SocialLink.objects.create(
            user_profile=self.profile,
            platform='linkedin',
            url='https://linkedin.com/in/testuser'
        )
        self.assertEqual(social_link.platform, 'linkedin')
        self.assertEqual(social_link.url, 'https://linkedin.com/in/testuser')

    def test_unique_platform_per_profile(self):
        SocialLink.objects.create(
            user_profile=self.profile,
            platform='linkedin',
            url='https://linkedin.com/in/testuser'
        )
        with self.assertRaises(IntegrityError):
            SocialLink.objects.create(
                user_profile=self.profile,
                platform='linkedin',
                url='https://linkedin.com/in/testuser2'
            )

    def test_multiple_platforms(self):
        platforms = ['linkedin', 'github', 'twitter']
        for platform in platforms:
            SocialLink.objects.create(
                user_profile=self.profile,
                platform=platform,
                url=f'https://{platform}.com/testuser'
            )
        self.assertEqual(self.profile.social_links.count(), 3)


class ReviewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123'
        )
        self.profile = UserProfile.objects.create(
            user=self.user,
            name='Test User',
            job_title='Developer',
            job_specialization='Web'
        )

    def test_create_review(self):
        review = Review.objects.create(
            profile=self.profile,
            reviewer_name='Client Name',
            rating=5,
            comment='Excellent work!'
        )
        self.assertEqual(review.rating, 5)
        self.assertEqual(review.comment, 'Excellent work!')

    def test_rating_update(self):
        # Create first review
        Review.objects.create(
            profile=self.profile,
            reviewer_name='Client 1',
            rating=5,
            comment='Excellent!'
        )
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.rating, 5.0)

        # Create second review
        Review.objects.create(
            profile=self.profile,
            reviewer_name='Client 2',
            rating=4,
            comment='Very good!'
        )
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.rating, 4.5)

    def test_invalid_rating(self):
        with self.assertRaises(ValidationError):
            review = Review(
                profile=self.profile,
                reviewer_name='Client',
                rating=6,  # Invalid rating > 5
                comment='Test'
            )
            review.full_clean()  # This will trigger validation


class ProfileShareTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123'
        )
        self.profile = UserProfile.objects.create(
            user=self.user,
            name='Test User',
            job_title='Developer',
            job_specialization='Web'
        )

    def test_create_profile_share(self):
        share = ProfileShare.objects.create(
            profile=self.profile,
            recipient_email='client@example.com',
            expires_at=timezone.now() + datetime.timedelta(days=7)
        )
        self.assertIsNotNone(share.share_token)
        self.assertFalse(share.is_verified)

    def test_share_validity(self):
        # Test valid share
        valid_share = ProfileShare.objects.create(
            profile=self.profile,
            recipient_email='client@example.com',
            expires_at=timezone.now() + datetime.timedelta(days=7)
        )
        self.assertTrue(valid_share.is_valid())

        # Test expired share
        expired_share = ProfileShare.objects.create(
            profile=self.profile,
            recipient_email='client2@example.com',
            expires_at=timezone.now() - datetime.timedelta(days=1)
        )
        self.assertFalse(expired_share.is_valid())

    def test_share_token_uniqueness(self):
        share1 = ProfileShare.objects.create(
            profile=self.profile,
            recipient_email='client1@example.com',
            expires_at=timezone.now() + datetime.timedelta(days=7)
        )
        share2 = ProfileShare.objects.create(
            profile=self.profile,
            recipient_email='client2@example.com',
            expires_at=timezone.now() + datetime.timedelta(days=7)
        )
        self.assertNotEqual(share1.share_token, share2.share_token)


class APITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123'
        )
        self.profile = UserProfile.objects.create(
            user=self.user,
            name='Test User',
            job_title='Developer',
            job_specialization='Web'
        )
        self.client.force_authenticate(user=self.user)

    def test_get_profile(self):
        url = reverse('profile-detail', kwargs={'pk': self.profile.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Test User')

    def test_update_profile(self):
        url = reverse('profile-update', kwargs={'pk': self.profile.pk})
        data = {
            'name': 'Updated Name',
            'job_title': 'Senior Developer'
        }
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Updated Name')

    def test_unauthorized_access(self):
        self.client.logout()
        url = reverse('profile-detail', kwargs={'pk': self.profile.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_share_link(self):
        url = reverse('create-share-link')
        data = {
            'email': 'client@example.com'  # Changed from recipient_email to email
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('share_token', response.data)

    def test_verify_share_link(self):
        share = ProfileShare.objects.create(
            profile=self.profile,
            recipient_email='client@example.com',
            expires_at=timezone.now() + timezone.timedelta(days=7)
        )
        url = reverse('verify-share-link', kwargs={'token': share.share_token})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
