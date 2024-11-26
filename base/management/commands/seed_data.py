import random, string
import uuid
from django.db import IntegrityError
from faker import Faker
# from faker_vehicle import VehicleProvider
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.management.base import BaseCommand
from base.models import Favorite, Follow, Listing, ListingApplication, PromoteListing, Rating, Report, SuspendedUser, UserAccount, UserProfile, UserVerification, UserApplication

class Command(BaseCommand):
    help = "Seed database with fake data for UserAccount and related models"

    def add_arguments(self, parser):
        parser.add_argument('--users', type=int, default=20, help="Number of users to create")
        parser.add_argument('--reports', type=int, default=5, help="Number of reports to create")

    def handle(self, *args, **options):
        fake = Faker()
        # fake.add_provider(VehicleProvider)
        num_users = options['users']
        num_reports = options['reports']

        self.stdout.write(f"Seeding {num_users} users and {num_reports} reports...")

        for _ in range(num_users):
            # Create UserAccount
            email = fake.unique.email()
            google_id = ''.join(random.choices(string.ascii_letters + string.digits, k=15)) if random.choice([True, False]) else None

            user = UserAccount.objects.create_user(
                email=email,
                password=fake.password(length=12),
                google_id=str(uuid.uuid4()) if random.choice([True, False]) else None
            )

            # Set additional fields after the user is created
            user.google_id = google_id
            role = random.choice(['is_reviewer', 'is_assumee', 'is_assumptor'])
            user.is_reviewer = (role == 'is_reviewer')
            user.is_assumee = (role == 'is_assumee')
            user.is_assumptor = (role == 'is_assumptor')
            user.is_active = True
            user.save()

            # Ensure UserProfile is created or linked to UserAccount
            mobile_number = f"+639{fake.random_int(100000000, 999999999)}"
            cebu_districts = [
                "Lahug", "Banilad", "Capitol Site", "Talamban",
                "Mabolo", "Basak", "Pardo", "Guadalupe", "Labangon", "Tisa"
            ]

            # Create UserProfile for each user
            profile = UserProfile.objects.create(
                user_id=user,  # Link UserProfile to UserAccount
                user_prof_fname=fake.first_name(),
                user_prof_lname=fake.last_name(),
                user_prof_gender=random.choice(['Male', 'Female']),
                user_prof_dob=fake.date_of_birth(minimum_age=18, maximum_age=80),
                user_prof_mobile=mobile_number,
                user_prof_address=f"{fake.street_address()}, {random.choice(cebu_districts)}, Cebu City, Cebu",
                user_prof_pic=fake.image_url(),
                user_prof_valid_id=fake.image_url(),
            )



            # Create UserVerification
            UserVerification.objects.create(
                user_verification_email=email,
                user_id=user,
                user_verification_is_verified=random.choice([True, False]),
                user_verification_expires_at = timezone.now() + timedelta(days=7)

            )

            # Create UserApplication
            UserApplication.objects.create(
                user_id=user,
                user_app_status=random.choice(['PENDING', 'APPROVED', 'REJECTED']),
                user_app_approved_at=None if random.choice([True, False]) else datetime.now(),
                user_app_reviewer_id=UserAccount.objects.filter(is_reviewer=True).order_by('?').first(),
            )

            # users = UserAccount.objects.all()  # Get all created users
            # for _ in range(num_users):  # Create random follow relationships
            #     follower = random.choice(users)
            #     following = random.choice(users)
                
            #     # Ensure a user doesn't follow themselves
            #     while follower == following:
            #         following = random.choice(users)
                
            #     # Check if the follow relationship already exists
            #     if not Follow.objects.filter(follower_id=follower, following_id=following).exists():
            #         Follow.objects.create(follower_id=follower, following_id=following)

            users = UserAccount.objects.all()  # Get all created users
            for _ in range(num_users):  # Create random follow relationships
                follower = random.choice(users)
                following = random.choice(users)

                # Ensure a user doesn't follow themselves
                while follower == following:
                    following = random.choice(users)

                # Ensure both users have profiles
                if not hasattr(follower, 'profile'):
                    # Create profile if it doesn't exist
                    UserProfile.objects.create(
                        user_id=follower,  # Link the profile to the user account
                        user_prof_fname=fake.first_name(),
                        user_prof_lname=fake.last_name(),
                        user_prof_gender=random.choice(['Male', 'Female']),
                        user_prof_dob=fake.date_of_birth(minimum_age=18, maximum_age=80),
                        user_prof_mobile=f"+639{fake.random_int(100000000, 999999999)}",
                        user_prof_address=f"{fake.street_address()}, Cebu City",
                        user_prof_pic=fake.image_url(),
                        user_prof_valid_id=fake.image_url(),
                    )

                if not hasattr(following, 'profile'):
                    # Create profile for following user if it doesn't exist
                    UserProfile.objects.create(
                        user_id=following,
                        user_prof_fname=fake.first_name(),
                        user_prof_lname=fake.last_name(),
                        user_prof_gender=random.choice(['Male', 'Female']),
                        user_prof_dob=fake.date_of_birth(minimum_age=18, maximum_age=80),
                        user_prof_mobile=f"+639{fake.random_int(100000000, 999999999)}",
                        user_prof_address=f"{fake.street_address()}, Cebu City",
                        user_prof_pic=fake.image_url(),
                        user_prof_valid_id=fake.image_url(),
                    )

                # Check if the follow relationship already exists
                if not Follow.objects.filter(follower_id=follower, following_id=following).exists():
                    Follow.objects.create(follower_id=follower, following_id=following)



             # Example for creating a Listing or other data related to the User
            category_choices = ['Real Estate', 'Motorcycle', 'Car']
            category = fake.random_element(elements=category_choices)

            car_makes = ["Toyota", "Honda", "Ford", "BMW", "Chevrolet", "Mercedes", "Audi", "Tesla"]
            car_models = ["Corolla", "Civic", "Mustang", "X5", "Camaro", "A4", "Model S", "S-Class"]

            motorcycle_makes = ["Harley-Davidson", "Honda", "Yamaha", "Ducati", "Kawasaki", "Suzuki"]
            motorcycle_models = ["Sportster", "CBR600", "Ninja ZX-10R", "Panigale V4", "R1", "GSX-R1000"]

            cebu_districts = [
                    "Lahug", "Banilad", "Capitol Site", "Talamban",
                    "Mabolo", "Basak", "Pardo", "Guadalupe", "Labangon", "Tisa"
                ]

            if category == 'Real Estate':
                # Generate data for Real Estate
                list_content = {
                    "year": fake.year(),
                    "price": fake.random_int(min=100000, max=1000000),
                    "title": f"{fake.word()} House in {fake.city()}",
                    "images": [fake.image_url() for _ in range(15)],  # 15 images
                    "lotArea": fake.random_int(min=50, max=1000),
                    "bedrooms": f"{fake.random_int(1, 5)} Bedrooms",
                    "category": category,
                    "address" : f"{fake.street_address()}, {random.choice(cebu_districts)}, Cebu City, Cebu",
                    "bathrooms": f"{fake.random_int(1, 5)} Bathrooms",
                    "documents": f"https://example.com/{fake.uuid4()}.pdf",
                    "floorArea": fake.random_int(min=50, max=5000),
                    "description": fake.text(),
                    "downPayment": fake.random_int(min=50000, max=200000),
                    "loanDuration": fake.random_int(min=12, max=60),
                    "parkingSpace": fake.random_int(min=1, max=5),
                    "monthlyPayment": fake.random_int(min=1000, max=20000),
                    "totalPaymentMade": fake.random_int(min=500000, max=5000000),
                    "numberOfMonthsPaid": fake.random_int(min=1, max=60)
                }

            elif category == 'Motorcycle':
                make = random.choice(motorcycle_makes)
                model = random.choice(motorcycle_models)
                list_content = {
                    "year": fake.year(),
                    "color": fake.color_name(),
                    "make": make,
                    "model": model,
                    "price": fake.random_int(min=5000, max=20000),
                    "title": f"{make} {model} {fake.year()}",
                    #"title" : fake.vehicle_year_make_model(),
                    "images": [fake.image_url() for _ in range(15)],  # 15 images
                    "mileage": f"{fake.random_int(min=100000, max=150000)} km",
                    "category": category,
                    "address" : f"{fake.street_address()}, {random.choice(cebu_districts)}, Cebu City, Cebu",
                    "fuelType": fake.random_element(elements=["Gasoline", "Diesel", "LPG", "Hybrid", "Electric"]),
                    "documents": f"https://example.com/{fake.uuid4()}.pdf",
                    "description": fake.text(),
                    "downPayment": fake.random_int(min=1000, max=5000),
                    "loanDuration": fake.random_int(min=12, max=60),
                    "transmission": fake.random_element(elements=["Automatic", "Manual"]),
                    "monthlyPayment": fake.random_int(min=500, max=5000),
                    "totalPaymentMade": fake.random_int(min=5000, max=50000),
                    "numberOfMonthsPaid": fake.random_int(min=1, max=60)
                }

            elif category == 'Car':
                make = random.choice(car_makes)
                model = random.choice(car_models)
                list_content = {
                    "year": fake.year(),
                    "color": fake.color_name(),
                    "make": make,
                    "model": model,
                    "price": fake.random_int(min=5000, max=50000),
                    "title": f"{make} {model} {fake.year()}",
                    #"title" : fake.vehicle_year_make_model(),
                    "images": [fake.image_url() for _ in range(15)],  # 15 images
                    "address": fake.address(),
                    "mileage": f"{fake.random_int(min=100000, max=150000)} km",
                    "category": category,
                    "address" : f"{fake.street_address()}, {random.choice(cebu_districts)}, Cebu City, Cebu",
                    "fuelType": fake.random_element(elements=["Gasoline", "Diesel", "LPG", "Hybrid", "Electric"]),
                    "documents": f"https://example.com/{fake.uuid4()}.pdf",
                    "description": fake.text(),
                    "downPayment": fake.random_int(min=1000, max=10000),
                    "loanDuration": fake.random_int(min=12, max=60),
                    "transmission": fake.random_element(elements=["Automatic", "Manual"]),
                    "monthlyPayment": fake.random_int(min=500, max=5000),
                    "totalPaymentMade": fake.random_int(min=5000, max=50000),
                    "numberOfMonthsPaid": fake.random_int(min=1, max=60)
                }

            # Generate a random duration for the listing (e.g., 1-30 days from now)
            list_duration = datetime.now() + timedelta(days=fake.random_int(1, 30))

            # Create the Listing instance
            listing = Listing.objects.create(
                list_id=uuid.uuid4(),
                list_content=list_content,
                list_status=fake.random_element(elements=[status[0] for status in Listing.STATUS_CHOICES]),
                list_duration=list_duration,
                user_id=user  # Linking listing to the user
            )

            promote_start = datetime.now() + timedelta(days=fake.random_int(1, 7))  # Start within 1 week
            promote_end = promote_start + timedelta(days=fake.random_int(7, 30))  # End between 7 and 30 days after start

            PromoteListing.objects.create(
                prom_start=promote_start,
                prom_end=promote_end,
                list_id=listing
            )


            listing = Listing.objects.order_by('?').first()  # Randomly pick a listing

            # Randomly select a reviewer (if you want a reviewer, else make it null)
            reviewer = UserAccount.objects.filter(is_reviewer=True).order_by('?').first()  # Random staff member as reviewer

            # Randomly select a status from the STATUS_CHOICES
            status = random.choice([choice[0] for choice in ListingApplication.STATUS_CHOICES])

            # Optionally, create a random reason (or leave it null)
            reason = fake.sentence() if random.choice([True, False]) else None  # Randomly decide if there should be a reason

            # Create the ListingApplication entry
            ListingApplication.objects.create(
                list_app_status=status,
                list_app_date=fake.date_this_year(),  # Random date in this year
                list_id=listing,
                list_app_reviewer_id=reviewer,  # Could be None if you want some without a reviewer
                list_reason=reason
            )
            

            user = UserAccount.objects.order_by('?').first()

            # Select a random listing
            listing = Listing.objects.order_by('?').first()

            # Check if the favorite relationship already exists between the user and the listing
            if not Favorite.objects.filter(list_id=listing, user_id=user).exists():
                # Create the favorite relationship if it doesn't already exist
                Favorite.objects.create(
                    list_id=listing,
                    user_id=user,
                    fav_date=fake.date_this_year()  # Random date within this year
                )



            # Fetch random users
            from_user = UserAccount.objects.order_by('?').first()
            to_user = UserAccount.objects.exclude(id=from_user.id).order_by('?').first()

            # Check if a Rating already exists for this pair
            existing_rating = Rating.objects.filter(from_user_id=from_user, to_user_id=to_user).exists()

            if not existing_rating:
                try:
                    # Create a new Rating
                    Rating.objects.create(
                        from_user_id=from_user,  # Assign actual UserAccount instance
                        to_user_id=to_user,      # Assign actual UserAccount instance
                        rating_value=random.choice([1, 2, 3, 4, 5]),  # Random rating value
                        review_comment=fake.text()  # Optional review comment
                    )
                    print(f"Successfully created rating from {from_user} to {to_user}")
                except IntegrityError as e:
                    print(f"Failed to create rating: {e}")
            else:
                print(f"Rating from {from_user} to {to_user} already exists.")



            users = list(UserAccount.objects.all())
            for _ in range(num_reports):
                reported_user = random.choice(users)
                reporter = random.choice(users)

                # Ensure the reported user and reporter are not the same
                while reported_user == reporter:
                    reporter = random.choice(users)

                reviewer = UserAccount.objects.filter(is_reviewer=True).order_by('?').first()

                # Randomly select a status for the report
                report_status = random.choice(['PENDING', 'APPROVED', 'REJECTED'])

                issue_type_choices = [
                    'Fraud', 'Scam', 'Nudity', 'False Information', 
                    'Hate Speech', 'Harassment', 'Violence', 'Spam', 'other'
                ]

                # Create the Report instance
                report = Report.objects.create(
                    report_details={
                        "reported_user_id": reported_user.id,
                        "reporter_id": reporter.id,
                        "describe": fake.text(),
                        "issue_type": random.choice(issue_type_choices),
                        "images": [fake.image_url() for _ in range(5)],
                    },
                    reviewer=reviewer,
                    report_status=report_status,
                    report_reason=fake.sentence() if report_status != 'PENDING' else None,
                )

                if report_status == 'APPROVED':
                    report.check_suspension()

            # Output suspended users
            suspended_users = SuspendedUser.objects.all()
            self.stdout.write(self.style.SUCCESS(f"Suspended Users: {len(suspended_users)}"))

            self.stdout.write(self.style.SUCCESS(f"Successfully seeded {num_users} users and {num_reports} reports!"))

        self.stdout.write(self.style.SUCCESS(f"Successfully seeded {num_users} users!"))
