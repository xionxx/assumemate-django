import random, string
import uuid
from django.db import IntegrityError
from faker import Faker
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
        num_users = options['users']

        self.stdout.write(f"Seeding {num_users} users ")

        for _ in range(num_users):
            # Create UserAccount
            email = fake.unique.email()
            # google_id = ''.join(random.choices(string.ascii_letters + string.digits, k=15)) if random.choice([True, False]) else None

            user = UserAccount.objects.create_user(
                email=email,
                password="123456",
                google_id=str(uuid.uuid4()) if random.choice([True, False]) else None
            )

            # Set additional fields after the user is created
            user.google_id = None
            role = random.choice(['is_reviewer', 'is_assumee', 'is_assumptor'])
            user.is_reviewer = (role == 'is_reviewer')
            user.is_assumee = (role == 'is_assumee')
            user.is_assumptor = (role == 'is_assumptor')
            user.is_active = True
            user.save()

            # Ensure UserProfile is created or linked to UserAccount
            mobile_number = f"+639{fake.random_int(100000000, 999999999)}"
            cebu_districts = [
                "Lahug", "Banilad", "Capitol Site", "Talamban", "Talisay",
                "Mabolo", "Basak", "Pardo", "Guadalupe", "Labangon", "Tisa"
            ]

            valid_id = [
                "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794665/valid%20id/vzuz3mp8nvkppajp7e3u.webp",
                "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794668/valid%20id/njicmnxl3e2im9p5syp7.png", 
                
                ]
            
            profile_pic = [
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794906/2byb2/twwkx8mejznvxn9gfiow.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794906/2byb2/x4pkjbevum21el7harsa.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794905/2byb2/mzia1hw5ea2c3t4gwtjx.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794905/2byb2/pck2u4ysekp0irlo6nas.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794905/2byb2/v0bzxksf3wzx4gunehpw.jpg",
                    "https://res.cloudinary.com/dbroe2hjh/image/upload/v1730772862/user_images/Aeri%20Uchinaga%20%2817%29/iyrpgtrgq8l9fgvpxezn.jpg",
                    "https://res.cloudinary.com/dbroe2hjh/image/upload/v1730772864/user_images/Aeri%20Uchinaga%20%2817%29/takbpwz1odxy1dcx2bha.jpg",
                ]
            
            b_profile_pic = [
                "https://res.cloudinary.com/dbroe2hjh/image/upload/v1732544151/user_images/Patricia%20Divine%20Delar%20%281%29/knpsbm5j94ezwd5vka0l.jpg",
                "https://res.cloudinary.com/dbroe2hjh/image/upload/v1732585399/user_images/Jericho%20Cenita%20%2823%29/xn3hkqgsgtbltwlrgo0b.jpg",
                "https://res.cloudinary.com/dbroe2hjh/image/upload/v1732544366/user_images/Patricia%20Divine%20Delar%20%281%29/mfhoq6bhsyhtn1vgxepy.jpg",
                "https://res.cloudinary.com/dbroe2hjh/image/upload/v1727335909/user_images/Yushi%20Tokuno%20%2845%29/khmzwx39maejglejnkeq.jpg",
                "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794906/2byb2/rxfve1fkgrhtnz1e5fr5.webp",
                "https://res.cloudinary.com/dbroe2hjh/image/upload/v1731521687/user_images/Patricia%20Divine%20Delar%20%281%29/ttmucxvvv1cum6m0snrz.jpg",
                "https://res.cloudinary.com/dbroe2hjh/image/upload/v1731100937/user_images/Patricia%20Divine%20Delar%20%281%29/m38nyhesrg5emlwmp0f8.jpg"
            ]
            
            valid_id_images = random.choice(valid_id)
            selected_profile_pic = random.choice(profile_pic) if random.choice(['Male', 'Female']) == 'Female' else random.choice(b_profile_pic)
            # b_selected_profile_pic = random.choice(b_profile_pic)

            # Create UserProfile for each user
            profile = UserProfile.objects.create(
                user_id=user,  # Link UserProfile to UserAccount
                user_prof_fname=fake.first_name(),
                user_prof_lname=fake.last_name(),
                user_prof_gender=random.choice(['Male', 'Female']),
                user_prof_dob=fake.date_of_birth(minimum_age=18, maximum_age=80),
                user_prof_mobile=mobile_number,
                user_prof_address=f"{fake.street_address()}, {random.choice(cebu_districts)}, Cebu City, Cebu",
                user_prof_pic=selected_profile_pic,
                user_prof_valid_pic = selected_profile_pic,
                user_prof_valid_id=valid_id_images,
            )



            # Create UserVerification
            if user.is_assumee or user.is_assumptor:
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
                    user_app_approved_at=None if random.choice([True, False]) else timezone.now(),
                    user_app_reviewer_id=UserAccount.objects.filter(is_reviewer=True).order_by('?').first(),
                )

            
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
                        user_prof_pic=selected_profile_pic ,
                        user_prof_valid_id=valid_id_images,
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
                        user_prof_pic=selected_profile_pic ,
                        user_prof_valid_id=valid_id_images,
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

            car_picture = [
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792053/Car/tpundt88zb2nyj2y3umb.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792048/Car/eanmahuvb6rro7axma74.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792048/Car/o7mzxsyruzxmh3od6hve.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792048/Car/i2tcg1ff2gjwrjdb0qpl.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792048/Car/jjyxmrykm9oebrsci5gp.webp",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792048/Car/faw9gdnudfdtej0mhgxp.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792048/Car/zenhxnki5ovebtqy08ze.webp",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792047/Car/ergkoqhhgr7avuvaca6k.avif",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792047/Car/ou9choywfhzspo6euunz.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792047/Car/gdfxivtlrfnjvn85r7ya.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792047/Car/vr0ks35lt3trnxypdvnx.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792047/Car/nhwl3xyonmmmew8xzdye.webp",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732792047/Car/ozljikyblpmiv35vesz4.jpg"
                ]

            motor_picture = [
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793790/motorcycle/wvjn2kigbvwpzj1boiyf.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793791/motorcycle/uoocd9yvxqjt0hc7aeyd.webp",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793790/motorcycle/vqqzb4dsorp0iigwzwoq.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793790/motorcycle/g6ky9w3eexnywnekt33e.webp",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793790/motorcycle/jt19sh5o3xphx0bbk79x.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793790/motorcycle/ccbo8it8kwq0ho9mdspj.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793790/motorcycle/ps2ylflqkrb76fivumds.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793789/motorcycle/b1ibjppj92c3eq7hmfbl.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793789/motorcycle/ziwkovtwalqnd7jcrdvn.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793789/motorcycle/cg37bfpvuignw8gidreq.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793789/motorcycle/xdpfu5cgxrn5hy9dkbjw.webp",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732793789/motorcycle/aiafoycmw1frxzvpyxh3.jpg"
                ]
            
            real_estate_picture = [
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794289/real%20estate/h7rsmujdxxbgjufu9ep3.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794289/real%20estate/h7rsmujdxxbgjufu9ep3.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794289/real%20estate/fqlhuic7aagrvdv5xeei.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794288/real%20estate/cvqyt9v6ichtsa1qwk2w.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794288/real%20estate/ldyhiilbtl5vez7jigib.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794288/real%20estate/nh3cmpuhgu6wljm61zdt.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794288/real%20estate/y94lpf1jpjlnuhqwkkvo.webp",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794288/real%20estate/yang4oz4gk8klwzbkzf5.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794287/real%20estate/op2mmvlzb5muzyehh3nc.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794287/real%20estate/ejcpbuwbxaegt3pwjons.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794287/real%20estate/a68yb3hzxittdio0sfcx.jpg",
                    "https://res.cloudinary.com/dj5ivpc7s/image/upload/v1732794286/real%20estate/ntx9my9x2khlphg0s9sc.jpg"
                ]
            
            selected_images = random.sample(car_picture, 4)
            selected_motor_images = random.sample(motor_picture, 4)
            selected_real_estate_images = random.sample(real_estate_picture, 4)

            document_url = f"https://example.com/{uuid.uuid4()}.pdf"

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
                    "offer_allowed": random.choice([True, False]),
                    "images": selected_real_estate_images,
                    "lotArea": fake.random_int(min=50, max=1000),
                    "bedrooms": f"{fake.random_int(1, 5)} Bedrooms",
                    "category": category,
                    "address" : f"{fake.street_address()}, {random.choice(cebu_districts)}, Cebu City, Cebu",
                    "bathrooms": f"{fake.random_int(1, 5)} Bathrooms",
                    "documents": document_url,
                    "floorArea": fake.random_int(min=50, max=5000),
                    "description": fake.text(),
                    "downPayment": fake.random_int(min=50000, max=200000),
                    "loanDuration": fake.random_int(min=12, max=60),
                    "parkingSpace": fake.random_int(min=1, max=5),
                    "monthlyPayment": fake.random_int(min=1000, max=20000),
                    "totalPaymentMade": fake.random_int(min=500000, max=5000000),
                    "numberOfMonthsPaid": fake.random_int(min=1, max=60)
                }

                list_content["reservation"] = float(int(list_content["price"] * fake.random.uniform(0.1, 0.5)))

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
                    "offer_allowed": random.choice([True, False]),
                    #"title" : fake.vehicle_year_make_model(),
                    "images": selected_motor_images,
                    "mileage": f"{fake.random_int(min=100000, max=150000)} km",
                    "category": category,
                    "address" : f"{fake.street_address()}, {random.choice(cebu_districts)}, Cebu City, Cebu",
                    "fuelType": fake.random_element(elements=["Gasoline", "Diesel", "LPG", "Hybrid", "Electric"]),
                    "documents": document_url,
                    "description": fake.text(),
                    "downPayment": fake.random_int(min=1000, max=5000),
                    "loanDuration": fake.random_int(min=12, max=60),
                    "transmission": fake.random_element(elements=["Automatic", "Manual"]),
                    "monthlyPayment": fake.random_int(min=500, max=5000),
                    "totalPaymentMade": fake.random_int(min=5000, max=50000),
                    "numberOfMonthsPaid": fake.random_int(min=1, max=60)
                }

                list_content["reservation"] = list_content["price"] * fake.random.uniform(0.1, 0.5)

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
                    "offer_allowed": random.choice([True, False]),
                    #"title" : fake.vehicle_year_make_model(),
                    "images": selected_images,  # 15 images
                    "address": fake.address(),
                    "mileage": f"{fake.random_int(min=100000, max=150000)} km",
                    "category": category,
                    "address" : f"{fake.street_address()}, {random.choice(cebu_districts)}, Cebu City, Cebu",
                    "fuelType": fake.random_element(elements=["Gasoline", "Diesel", "LPG", "Hybrid", "Electric"]),
                    "documents": document_url,
                    "description": fake.text(),
                    "downPayment": fake.random_int(min=1000, max=10000),
                    "loanDuration": fake.random_int(min=12, max=60),
                    "transmission": fake.random_element(elements=["Automatic", "Manual"]),
                    "monthlyPayment": fake.random_int(min=500, max=5000),
                    "totalPaymentMade": fake.random_int(min=5000, max=50000),
                    "numberOfMonthsPaid": fake.random_int(min=1, max=60)
                }

                list_content["reservation"] = list_content["price"] * fake.random.uniform(0.1, 0.5)

            # Generate a random duration for the listing (e.g., 1-30 days from now)
            list_duration = timezone.now() + timedelta(days=fake.random_int(1, 30))

            # Create the Listing instance
            assumptor_users = UserAccount.objects.filter(is_assumptor=True)
            if not assumptor_users.exists():
                print("No assumptor users available.")
                continue

            new_listing = Listing.objects.create(
                list_id=uuid.uuid4(),
                list_content=list_content,
                list_status=fake.random_element(elements=[status[0] for status in Listing.STATUS_CHOICES]),
                list_duration=list_duration,
                user_id=random.choice(UserAccount.objects.filter(is_assumptor=True))   # Linking listing to the user
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


        self.stdout.write(self.style.SUCCESS(f"Successfully seeded {num_users} users!"))
