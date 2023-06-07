# Download the helper library from https://www.twilio.com/docs/python/install
from school import settings
from twilio.rest import Client
# Set environment variables for your credentials
# Read more at http://twil.io/secure


def send_sms_notification(patient, staff_member):
    relatedRecipient_firstName = staff_member.get("first_name")
    relatedRecipient_lastName = staff_member.get("last_name")
    patientNumber = ''.join(list(patient.get("contact_number")))
    staff_memberNumber = ''.join(list(staff_member.get("contact_number")))
    
    account_sid = settings.TWILIO_ACCOUNT_SID
    auth_token = settings.TWILIO_AUTH_TOKEN
    client = Client(account_sid, auth_token)
    message = client.messages.create(
    body=f"""
Hi {patient.get('patient_first_name')}, 

An appointment has been successfully setup with Dr,{relatedRecipient_firstName} {relatedRecipient_lastName} on {patient.get('appointment_date')} at assigned time slot of {patient.get('appointment_slot')}. 

Our Team will be waiting for your arrival. Thanks for choosing us.

Kind regards,
project Support Team
""",
    from_="+13614597582",
    to=patientNumber,
    
    body=f"""
Hi {staff_member.get('first_name')}, 

An appointment has been successfully setup with the client. 
please check the dashboard for more information.

Kind regards,
project Support Team
"""
)
#print(message.sid)







