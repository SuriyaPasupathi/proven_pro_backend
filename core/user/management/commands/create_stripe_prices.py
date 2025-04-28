from django.core.management.base import BaseCommand
import stripe
from django.conf import settings

stripe.api_key = settings.STRIPE_SECRET_KEY

class Command(BaseCommand):
    help = 'Creates Stripe prices for products'

    def handle(self, *args, **kwargs):
        try:
            # Create Standard price
            standard_price = stripe.Price.create(
                unit_amount=1000,  # $10.00
                currency='usd',
                product='prod_SCAQJi03mzQouM',  # Your standard product ID
                nickname='Standard Plan'
            )

            # Create Premium price
            premium_price = stripe.Price.create(
                unit_amount=2000,  # $20.00
                currency='usd',
                product='prod_SCAQ2zgxrRt41A',  # Your premium product ID
                nickname='Premium Plan'
            )

            self.stdout.write(self.style.SUCCESS(f'Standard Price ID: {standard_price.id}'))
            self.stdout.write(self.style.SUCCESS(f'Premium Price ID: {premium_price.id}'))
            
            self.stdout.write(self.style.SUCCESS(
                'Update your STRIPE_PRICE_IDS in settings.py with these values'
            ))

        except stripe.error.StripeError as e:
            self.stdout.write(self.style.ERROR(f'Error: {str(e)}'))