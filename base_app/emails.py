from school import settings
from rest_framework.response import Response
from django.core.mail import send_mail


#### Email seeding functions #####


# Email notification after signup
def send_email_notification(recipient_list, fetched_activation_OTP):
    
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Account Update Notification"
    message = f"""
    Hi, 
    
    Your Account activation key is {fetched_activation_OTP}.
    Enter the key on registration form.
     
    Thanks! Regards.
    TestProject Support Team
    """
    send_mail(subject, message, email_from, recipient_list)

    return True


# Email notification If user changes Profile information
def send_user_profile_update_notification(recipient_list):
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Account Update Notification"
    message = """
    Hi, 
    
    As per request we have updated your account information. 
    Please check your account and If you haven`t updated any information Please contact our Customer Support. 
     
    Thanks! Regards.
    TestProject Support Team
    """
    send_mail(subject, message, email_from, recipient_list)

    return True


# Password reset email
def send_forget_password_mail(recipient_list, uid, token):
    reset_password_link = f"http://127.0.0.1:5500/Change-Password/change_password_page.html?uid={uid}&token={token}"
    email_from = settings.DEFAULT_FROM_EMAIL
    send_mail(
        "Account Password Reset Notification",
        f"""
Hi {recipient_list.get('first_name')}, 

There was a request to change your password! 
Please click this link to change your password: {reset_password_link}

Kind regards,
TestProject Support Team
""",
        email_from,
        [recipient_list],
        fail_silently=False,
    )
    return True


# Email notification If user changes Profile information
def send_user_profile_delete_notification(recipient_list):
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Account Deletion Notification"
    message = f"""
    
Dear {recipient_list.get('first_name')},

We regret to inform you that your account with HeartBeat has been deleted as per your request. This action is irreversible, and all associated data and information have been permanently removed from our systems.
    
If you have any further queries or require assistance, please don't hesitate to reach out to our support team at {email_from}.
Thank you for being a part of HeartBeat. We appreciate your past support and wish you all the best in your future endeavors.

Kind regards,
TestProject Support Team

"""
    send_mail(subject, message, email_from, recipient_list)

    return True


# Email notification after signup
def send_email_notification_to_staff(staff_member):
    relatedRecipient_email = staff_member.get("email")
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Appointment update Notification"
    message = f"""
Hi {staff_member.get('first_name')}, 

An appointment has been successfully setup with the client. 
please check the dashboard for more information.

Kind regards,
TestProject Support Team
"""
    send_mail(subject, message, email_from, [relatedRecipient_email])

    return True


# Email notification after signup
def send_email_notification_to_patient(patient, staff_member):
    relatedRecipient_firstName = staff_member.get("first_name")
    relatedRecipient_lastName = staff_member.get("last_name")
    patient_email = patient.get("email")
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Appointment update Notification"
    message = f"""
Hi {patient.get('patient_first_name')}, 

An appointment has been successfully setup with Dr.{relatedRecipient_firstName} {relatedRecipient_lastName} on {patient.get('appointment_date')} at assigned time slot of {patient.get('appointment_slot')}. 

Our Team will be waiting for your arrival. Thanks for choosing us.

Kind regards,
TestProject Support Team
"""
    send_mail(subject, message, email_from, [patient_email])

    return True
