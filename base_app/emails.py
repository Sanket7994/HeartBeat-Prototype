import json
from decimal import Decimal, ROUND_DOWN
from school import settings
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import EmailMessage
from django.core.mail import EmailMultiAlternatives



#### Email seeding functions #####


# Email notification after signup
def send_email_notification(recipient_list, fetched_activation_OTP):
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Account Update Notification"
    html_body = f"""
    Hi
    Thank you for choosing TestProject. Use the following OTP to complete your Sign Up procedures. 
    OTP is valid for 10 minutes.
    {fetched_activation_OTP}
    Regards, 
    TestProject

    """
    send_mail(subject, html_body, email_from, recipient_list)

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


def send_forget_password_mail(user, uid, token):
    reset_password_link = f"http://127.0.0.1:5502/template/pages/samples/change-password.html?uid={uid}&token={token}"
    email_from = settings.DEFAULT_FROM_EMAIL
    send_mail(
        "Account Password Reset Notification",
        f"""
Hi {user.first_name},

There was a request to change your password! 
Please click this link to change your password: {reset_password_link}

Kind regards,
TestProject Support Team
""",
        email_from,
        [user.email],
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
Hi {staff_member.get('staff_first_name')}, 

An appointment has been successfully setup with the client. 
please check the dashboard for more information.

Kind regards,
TestProject Support Team
"""
    send_mail(subject, message, email_from, [relatedRecipient_email])

    return True


# Email notification after signup
def send_email_notification_to_patient(patient, staff_member):
    relatedRecipient_firstName = staff_member.get("staff_first_name")
    relatedRecipient_lastName = staff_member.get("staff_last_name")
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


# Send payment link to client email address 
def send_pay_link_via_email(client, pay_link):
    client_email = client.get("patient_email")
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Pending Payment Notification Email"
    
    # Render the HTML template with the button
    html_message = render_to_string(
        "../templates/pay_link_email.html",
        {"client": client, "pay_link": pay_link}
    )
    
    # Extract the plain text content from the HTML
    plain_message = strip_tags(html_message)
    
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=email_from,
        recipient_list=[client_email],
        html_message=html_message
    )
    
    return True


# Send payment link to client email address 
def send_successful_purchase_email(client, pay_link):
    client_email = client.get("patient_email")
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Pending Payment Notification Email"
    
    # Render the HTML template with the button
    html_message = render_to_string(
        "../templates/pay_link_email.html",
        {"client": client, "pay_link": pay_link}
    )
    
    # Extract the plain text content from the HTML
    plain_message = strip_tags(html_message)
    
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=email_from,
        recipient_list=[client_email],
        html_message=html_message
    )
    return True


# Send PO request email with CSV file
def send_email_with_attachment(user, data, file=None):
    # Pre-calculate details for email
    purchase_order_id = data.purchase_order_id
    order_list = json.loads(data.order)
    order_count = len(order_list)
    total_payment_amount = Decimal(data.total_payment_amount)
    average_unit_price = (total_payment_amount / Decimal(order_count)).quantize(Decimal('0.00'), rounding=ROUND_DOWN)

    # Create the email message
    subject = 'New Medicine Batch Purchase Request'
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = user.get("email")
    
    context = {
        "user": user,
        "count": order_count,
        "purchase_order_id": purchase_order_id,
        "total_payment_amount": total_payment_amount,
        "average_unit_price": average_unit_price,
    }
    html_content = render_to_string("../templates/purchase_request.html", context)
    
    text_content = f"""
    Request for Approval: New Medicine Batch Purchase 
    
    Respected {user.get("first_name")}, 
    I hope this email finds you well. I am writing to request your approval for the purchase of a new batch of medicines. Following are some important Details regarding the Purchase order #{data.purchase_order_id}. 
    
    ---------------------------------------------------------------------------
    |                        ===  Order Summary ===                           |
    ---------------------------------------------------------------------------
    | Total Number of Products | Average Unit Price  | Total Payable Amount   |
    ---------------------------------------------------------------------------
    |      {order_count} Nos         |         ${average_unit_price}|     ${total_payment_amount}|
    ---------------------------------------------------------------------------
    
    If you have any questions or require further information, please feel free to reach out to me. Thank you for your attention to this matter. Your support is greatly appreciated! 
    
    Kind regards, 
    TestProject Support Team"""

    msg = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
    
    # Attach the file
    if file is not None:
        with open(file, 'rb') as f:
            msg.attach(file.split('/')[-1], f.read(), 'text/csv')
            
    # Attach the HTML content as an alternative to support both plain text and HTML
    msg.attach_alternative(html_content, "text/html")
    
    # Send the email
    msg.send()


        




