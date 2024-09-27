from io import BytesIO
import random, string, cloudinary, base64
from django.views.decorators.csrf import csrf_protect
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from django.db import IntegrityError
from smtplib import SMTPConnectError, SMTPException
from django.contrib.auth.decorators import user_passes_test, login_required
from django.utils import timezone
from datetime import timedelta
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.conf import settings
from django.core.mail import EmailMessage
from django.views.decorators.http import require_POST
from django.contrib import messages
from .permissions import IsAdminUser
from .models import Message, UserApplication, UserProfile, UserVerification
from rest_framework import viewsets, status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.files.base import ContentFile
from django.contrib.auth import login as login, authenticate, logout, get_user_model

UserModel = get_user_model()

def is_admin(user):
    return user.is_staff

def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation

    password = ''.join(random.choice(characters) for _ in range(length))

    return password

# Function to generate the PDF content
def create_pdf(user_profile, temp_password):
    buffer = BytesIO()

    # Generate the PDF using ReportLab
    pdf = canvas.Canvas(buffer)
    pdf.drawString(100, 750, "Assumemate Account Details")
    pdf.drawString(100, 730, f"Dear Mr/s. {user_profile.user_prof_lname},")
    pdf.drawString(100, 710, "We are thrilled to welcome you to Assumemate!")
    pdf.drawString(100, 690, "Below are the details for your Assumemate account:")
    pdf.drawString(100, 670, f"Name: {user_profile.user_prof_fname} {user_profile.user_prof_lname}")
    pdf.drawString(100, 650, f"Email Address: {user_profile.user_id.email}")
    pdf.drawString(100, 630, f"Temporary Password: {temp_password}")
    pdf.drawString(100, 610, "Please use this password to log in and change it immediately.")
    
    pdf.save()

    buffer.seek(0)  # Reset buffer to start

    return buffer

def encrypt_pdf(pdf_buffer, user_lastname, user_birthday):
    pdf_reader = PdfReader(pdf_buffer)
    pdf_writer = PdfWriter()

    for page in range(len(pdf_reader.pages)):
        pdf_writer.add_page(pdf_reader.pages[page])

    # Format the password by removing dashes from the birthday
    formatted_birthday = user_birthday.replace('-', '')  # Remove dashes
    encryption_password = f"{user_lastname}{formatted_birthday}"

    # Add password protection
    pdf_writer.encrypt(encryption_password)

    encrypted_pdf_buffer = BytesIO()
    pdf_writer.write(encrypted_pdf_buffer)
    encrypted_pdf_buffer.seek(0)  # Reset buffer to start

    return encrypted_pdf_buffer

def send_welcome_email(user_profile, user_account, temp_password):
    # Create the PDF content
    pdf_buffer = create_pdf(user_profile, temp_password)

    # Encrypt the PDF with the user's last name and formatted birthday
    user_lastname = user_profile.user_prof_lname
    user_birthday = user_profile.user_prof_dob  # Assuming you have birthday in user_profile
    encrypted_pdf_buffer = encrypt_pdf(pdf_buffer, user_lastname, user_birthday)

    # Email content
    message = (
        f'Dear Mr/s. {user_profile.user_prof_lname},\n\n'
        'We are thrilled to welcome you to Assumemate! '
        'Attached is a PDF document with your account details, protected by your last name and birthday.\n'
        'Please use the combination of your last name and birthday to access the document and change your temporary password immediately after logging in.\n\n'
        'Thank you for joining Assumemate!'
    )

    # Save the PDF as a file in memory to attach to the email
    pdf_filename = f"Assumemate_Account_Details_{user_profile.user_prof_lname}.pdf"
    pdf_file = encrypted_pdf_buffer

    try:
        # Send the email with the encrypted PDF attached
        email = EmailMessage(
            'Welcome to Assumemate - Your Account Details',
            message,
            settings.EMAIL_HOST_USER,
            [user_account.email]
        )
        email.attach(pdf_filename, pdf_file.getvalue(), 'application/pdf')
        email.send(fail_silently=False)

        print(f"Email sent to {user_account.email}")
        
    except Exception as e:
        print('Error sending welcome email with PDF:', e)
        return JsonResponse({'error': f'Error sending welcome email with PDF: {e}'})

@csrf_protect
def upperuser_register(request, user_type):
    if request.method == 'POST':
        try:
            fname = request.POST.get('fname').title()
            lname = request.POST.get('lname').title()
            gender = request.POST.get('gender').title()
            address = request.POST.get('address').title()
            dob = request.POST.get('bday')
            mobile = request.POST.get('phone')
            email = request.POST.get('email').lower()
            # image = request.FILES.get('imagefile')
            user_image = request.POST.get('user_image')
            password = generate_random_password()
            
            user = UserModel.objects.create(email=email, first_name=fname,
                                last_name=lname, is_superuser=True, is_active=True)
            
            if user_type == 'Admin':
                user.is_staff=True
            elif user_type == 'Reviewer':
                user.is_reviewer=True
            
            user.set_password(password)
            user.save()

            folder_name = f"{fname} {lname} ({user.id})"

            if user_image:
                try:
                    format, imgstr = user_image.split(';base64,') 
                    ext = format.split('/')[-1]  # Extract the image extension (jpeg, png, etc.)
                    # Decode the image
                    image_data = ContentFile(base64.b64decode(imgstr), name=f"user{user.id}_{fname}_{lname}.{ext}")

                    upload_result = cloudinary.uploader.upload(image_data, folder=f"user_images/{folder_name}")
                except Exception as e:
                    return JsonResponse({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

            image_json =  upload_result['secure_url'] if image_data else None

            profile = UserProfile.objects.create(user_prof_fname=fname, user_prof_lname=lname, user_prof_gender=gender, 
                                                 user_prof_dob=dob, user_prof_mobile=mobile, user_prof_address=address, 
                                                 user_prof_pic=image_json, user_id=user)
            
            profile.save()
            try:
                send_welcome_email(profile, user, password)
            except Exception as e:
                print(e)
                return JsonResponse({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            return JsonResponse({'message': 'User added successfully'}, status=status.HTTP_201_CREATED)

        except IntegrityError:
            return JsonResponse({'error': 'Email already exists.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@csrf_protect
def user_login(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        email = request.POST.get('emailaddress')
        password = request.POST.get('password')

        user = authenticate(request, email=email, password=password)
        print(user)
        if user is not None:
            login(request, user)
            return JsonResponse('admin_acc_create')
        else:
            print("Authentication failed")
            return JsonResponse({'auth_failed': 'Incorrect email or password'})
        
    return render(request, 'base/login.html')

@login_required(login_url='user_login')
def logout(request):
    logout(request)
    return redirect(user_login)

def approve_user(request, id):
    try:
        user = UserApplication.objects.get(user_prof_id=id)
        user.user_app_status = 'APPROVED'
        user.save()
        return
    except:
        return
    
def reject_user(request, id):
    try:
        user = UserApplication.objects.get(user_prof_id=id)
        user.user_app_status = 'REJECTED'
        user.save()
        return
    except:
        return 

###### render views ######.
def base(request):
    user_pic = UserProfile.objects.get(user_id=45)
    context = {'pic': user_pic.user_prof_pic}
    # context = {}
    return render(request, "base/home.html", context)

# @user_passes_test(is_admin)
# @login_required(login_url='user_login')
def admin_acc_create(request):
    context = {'nav': 'admin', 'user_type': 'Admin'}
    return render(request, 'base/add_upperuser.html', context)

def admin_acc_list(request):
    admin = UserModel.objects.filter(is_staff=True)
    context = {'admin': admin, 'nav': 'admin'}
    # context = {'nav': 'admin'}
    return render(request, 'base/admin_list.html', context)

def user_application_list(request):
    user_application = UserModel.objects.filter(is_staff=True)
    context = {'users': user_application, 'nav': 'user'}
    # context = {'nav': 'admin'}
    return render(request, 'base/users_list.html', context)

def reviewer_acc_list(request):
    reviewer = UserModel.objects.filter(is_reviewer=True)
    context = {'reviewer': reviewer, 'nav': 'reviewer'}
    # context = {'nav': 'admin'}
    return render(request, 'base/reviewer_list.html', context)

def reviewer_acc_create(request):
    context = {'nav': 'reviewer', 'user_type': 'Reviewer'}
    return render(request, 'base/add_upperuser.html', context)


