# This retrieves a Python logging instance (or creates it)
import logging

log = logging.getLogger(__name__)

# IMPORTS
import os
import csv
import json
from datetime import datetime
import requests
from django.http import JsonResponse
from decimal import Decimal
import stripe, logging
from django.core.exceptions import ObjectDoesNotExist
from datetime import timedelta
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from django.shortcuts import render
from django.db.models import F
from django.conf import settings
from .views import *
from .serializer import *


# Validation test for JWT authorization tokens
def validate_token(token):
    try:
        # Attempt to decode the access token
        access_token = AccessToken(token)
        # Check if the access token is expired
        is_access_token_expired = access_token.is_expired
        # If you need to check the expiration time explicitly, you can access the "exp" claim
        access_token_expiration_time = access_token.payload["exp"]
        # Optionally, you can also check the refresh token's expiration status
        refresh_token = RefreshToken(token)
        is_refresh_token_expired = refresh_token.is_expired
        # If you need to check the refresh token's expiration time explicitly
        refresh_token_expiration_time = refresh_token.payload["exp"]
        # Now, you can use the above variables to handle token expiration validation logic as needed
        if is_access_token_expired:
            print("Access token has expired.")
        else:
            print("Access token is still valid.")
        if is_refresh_token_expired:
            print("Refresh token has expired.")
        else:
            print("Refresh token is still valid.")
    except Exception as e:
        print(f"Token validation error: {str(e)}")


# Create pagination
def apply_pagination(self, request, Paginator, queryset, serializer, *args, **kwargs):
    set_limit = self.request.GET.get("limit")
    paginator = Paginator(queryset, set_limit)
    page_number = self.request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    meta_serializer = serializer(page_obj, many=True)

    return {
        "Page": {
            "totalRecords": queryset.count(),
            "current": page_obj.number,
            "next": page_obj.has_next(),
            "previous": page_obj.has_previous(),
            "totalPages": page_obj.paginator.num_pages,
        },
        "Result": meta_serializer.data,
    }


# JSON Decoder for Decimal Digits
class DecimalEncoder(json.JSONEncoder): 
    def default(self, o):
        if isinstance(o, Decimal):
            return str(o)
        return super().default(o)


# JSON Datetime encoder
class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


# Get difference between two or more Dates
def days_diff(a, b):
    return (
        datetime.strptime(a, "%d-%m-%Y %H:%M:%S")
        - datetime.strptime(b, "%d-%m-%Y %H:%M:%S")
    ).days


# Currency Exchange Rate API
def get_currency_exchange_rates(request, current_selected_currency, target_currency):
    if current_selected_currency is not None and target_currency is not None:
        url = f"https://api.exchangerate.host/convert?from={current_selected_currency}&to={target_currency}"
        response = requests.get(url)
        data = response.json()
        return JsonResponse(data)  # Return the data as a JSON response
    raise ValueError("This URL only supports non-null values.")


# Convert Dictionary to CSV file
def dict_to_csv(data, filename):
    fieldnames = list(data[0].keys())
    current_directory = os.getcwd()
    filepath = os.path.join(current_directory, filename)

    with open(filepath, "w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    return filepath


# Can retrieve collected data from either appointment or prescription unique identifiers
def fetch_master_data(appointment_id=None, prescription_id=None):
    # Creating an empty dictionary
    collection_dict = {}

    if appointment_id is not None:
        appointment = (
            PatientAppointment.objects.filter(appointment_id=appointment_id)
            .values()
            .first()
        )

        if appointment is not None:
            selected_procedures = MedicalProceduresTypes.objects.filter(
                procedure_choice_per_patient=appointment_id
            ).values()
            prescriptions = Prescription.objects.filter(
                appointment_id=appointment_id
            ).values()

            prescriptions_data = []
            for prescription in prescriptions:
                prescription_id = prescription["prescription_id"]
                prescription_data = (
                    Prescription.objects.filter(prescription_id=prescription_id)
                    .values()
                    .first()
                )
                prescriptions_data.append(prescription_data)

            staff_id = appointment["relatedRecipient_id"]
            consultant = (
                ClinicMember.objects.filter(staff_id=str(staff_id)).values().first()
            )
            clinic_id = consultant["clinic_name_id"]
            clinic = Clinic.objects.filter(clinic_id=str(clinic_id)).values().first()

            collection_dict["selected_procedures"] = selected_procedures
            collection_dict.update(appointment)
            collection_dict.update(consultant)
            collection_dict.update(clinic)

            prescription_data_dict = {}
            for i, prescription_data in enumerate(prescriptions_data):
                prescription_data_dict[f"prescription_{i+1}"] = prescription_data
                if i == len(prescription_data):
                    break
            collection_dict["prescription_data"] = prescription_data_dict

    elif prescription_id is not None:
        prescription = (
            Prescription.objects.filter(prescription_id=prescription_id)
            .values()
            .first()
        )
        if prescription is not None:
            appointment_id = prescription["appointment_id_id"]
            if appointment_id is not None:
                appointment = (
                    PatientAppointment.objects.filter(appointment_id=appointment_id)
                    .values()
                    .first()
                )
                consultant = (
                    ClinicMember.objects.filter(
                        staff_id=appointment["relatedRecipient_id"]
                    )
                    .values()
                    .first()
                )
                clinic = (
                    Clinic.objects.filter(clinic_id=consultant["clinic_name_id"])
                    .values()
                    .first()
                )
                if appointment is not None:
                    if "procedures" not in collection_dict:
                        selected_procedures = MedicalProceduresTypes.objects.filter(
                            procedure_choice_per_patient=appointment_id
                        ).values()
                        collection_dict["procedures"] = selected_procedures

                    if "appointment_id" not in collection_dict:
                        collection_dict.update(appointment)
                        collection_dict.update(consultant)
                        collection_dict.update(clinic)

                    if "prescription_id" not in collection_dict:
                        collection_dict.update(prescription)

    return collection_dict


# Function which eliminates string values with Truthy values
def clean_payment_data(data):
    cleaned_data = {}
    for key, value in data.items():
        if isinstance(value, dict):
            cleaned_data[key] = clean_payment_data(value)
        else:
            if value == "null":
                cleaned_data[key] = None
            elif value == "false":
                cleaned_data[key] = False
            elif value == "true":
                cleaned_data[key] = True
            else:
                cleaned_data[key] = value
    return cleaned_data


def validate_stripe_price_id(product_id):
    stripe.api_key = settings.STRIPE_SECRET_KEY
    try:
        stripe_data = stripe.Price.list(product=product_id)
        stripe_price_id = stripe_data.data[0].id
        return stripe_price_id
    except stripe.error.StripeError as error:
        print(f"Stripe Error: {error}")
        return None


def get_stripe_product_id(product_name):
    stripe.api_key = settings.STRIPE_SECRET_KEY
    try:
        # Retrieve a list of all products
        all_products = stripe.Product.list(limit=100)

        # Search for the product with the matching name
        for product in all_products.data:
            if product.name == product_name:
                return product.id
        return None
    except stripe.error.StripeError as e:
        print(f"Stripe Error: {e}")
        return None


# Function which creates a payment link from stripe
def create_payment_link(prescription_dict, return_items=False):
    # Set the Stripe API key
    stripe.api_key = settings.STRIPE_SECRET_KEY

    try:
        # Extract medication and service data from the prescription_dict
        product_data = json.loads(prescription_dict["medications_json"])
        service_data = list(prescription_dict["procedures"].values())

        # Initialize a list to store line items for the payment
        line_items = []

        # Process medication items
        for medicine in product_data:
            product_name = medicine["medicine_name"]
            validated_product_id = get_stripe_product_id(product_name)
            validated_price_id = validate_stripe_price_id(validated_product_id)

            if validated_price_id:
                # Create a line item for the medication
                payload = {
                    "price": validated_price_id,
                    "quantity": int(medicine.get("quantity", 0))
                }
                line_items.append(payload)

        # Process service items
        for service in service_data:
            service_name = service["procedure_choice"]
            validated_service_id = get_stripe_product_id(service_name)
            validated_price_id = validate_stripe_price_id(validated_service_id)

            if validated_price_id:
                payload = {
                    "price": validated_price_id,
                    "quantity": 1
                }
                line_items.append(payload)

        # Add an additional line item for appointment price (if available)
        appointment_price_id = prescription_dict["stripe_appointment_price_id"]
        if appointment_price_id:
            line_items.append({"price": str(appointment_price_id), "quantity": 1})
            
        # Create a payment link using the line items
        payment_link_payload = stripe.PaymentLink.create(line_items=line_items)
        payment_url = payment_link_payload["url"]

        # Return the requested data based on return_items parameter
        if return_items == "line_items":
            return line_items
        elif return_items == "payment_url":
            return payment_url

    except stripe.error.CardError as e:
        logging.error("A payment error occurred: {}".format(e))
        raise
    except stripe.error.InvalidRequestError as er:
        logging.error("An invalid request occurred: {}".format(er))
        raise
    except Exception as ex:
        logging.error("Error unrelated to Stripe: {}".format(str(ex)))
        raise



# Create or check Customer ID
def get_or_create_stripe_customer(prescription_dict):
    """Checking if the Customer ID exists in the current database, If Stripe Customer ID does not exist
    Or the Customer is New then save the Customer into local and stripe database for future
    """

    stripe.api_key = settings.STRIPE_SECRET_KEY
    try:
        # Check if customer exists in Stripe based on email
        customers = stripe.Customer.list(email=prescription_dict["patient_email"]).data
        if customers:
            customer_id = customers[0].id
        else:
            # Check if customer exists in local database
            try:
                customer = ClientDataCollectionPool.objects.get(
                    stripe_customer_id=str(prescription_dict["stripe_client_id"])
                )
                customer_id = customer.stripe_customer_id
                log.warning(
                    "%s already exists in ClientDataCollectionPool", customer_id
                )
            except ObjectDoesNotExist:
                # Create a new customer in Stripe
                shipping_address = json.loads(prescription_dict["shipping_address"])
                customer = stripe.Customer.create(
                    email=prescription_dict["patient_email"],
                    name=f"{prescription_dict['patient_first_name']} {prescription_dict['patient_last_name']}",
                    phone=prescription_dict["patient_contact_number"],
                    shipping={
                        "name": f"{prescription_dict['patient_first_name']} {prescription_dict['patient_last_name']}",
                        "address": {
                            "country": shipping_address["country"],
                            "state": shipping_address["state"],
                            "city": shipping_address["city"],
                            "line1": shipping_address["line1"],
                            "line2": shipping_address["line2"],
                            "postal_code": shipping_address["postal_code"],
                        },
                    },
                )
                related_prescription = Prescription.objects.get(
                    prescription_id=prescription_dict["prescription_id"]
                )
                prescription_data = {"stripe_client_id": str(customer.id)}

                # Update the prescription with the new Stripe customer ID
                serializer = PrescriptionSerializer(
                    related_prescription, data=prescription_data, partial=True
                )
                serializer.is_valid(raise_exception=True)
                serializer.save()

                customer_id = str(customer.id)
                log.info(
                    "New Stripe Customer ID created and added to the local database."
                )
        return customer_id
    except stripe.error.InvalidRequestError as e:
        logging.error("An invalid request occurred: %s", str(e))
        raise
    except Exception as ex:
        logging.error("Error unrelated to Stripe: %s", str(ex))
        raise


# Function which creates basic invoice from stripe and sends it to the customer
def send_stripe_invoice(data):
    stripe.api_key = settings.STRIPE_SECRET_KEY

    # Fetching necessary information to send invoice to customer
    customer_id = data["customer"]

    # fetching item details
    prescription_dict = fetch_master_data(
        appointment_id=None, prescription_id=str(data["client_reference_id"])
    )
    med_data = json.loads(prescription_dict["medications_json"])

    ITEM_PRICES = {med["medicine_name"]: med["stripe_price_id"] for med in med_data}
    # Create an Invoice
    invoice = stripe.Invoice.create(
        customer=customer_id,
        collection_method="send_invoice",
        days_until_due=30,
    )

    # Create an Invoice Item with the Price and Customer you want to charge
    stripe.InvoiceItem.create(
        customer=customer_id, price=ITEM_PRICES, invoice=invoice.id
    )

    # Send the Invoice
    stripe.Invoice.send_invoice(invoice.id)
    return


# Experimental Custom Invoice render function
def fetch_data_and_render_template(request, appointment_id, prescription_id):
    # Construct the API URL with the provided parameters
    api_url = f"http://127.0.0.1:8000/prescription/fetch/appointment_id={appointment_id}&prescription_id={prescription_id}"

    # Checking parameter type
    if appointment_id == "None":
        appointment_id = None
    if prescription_id == "None":
        prescription_id = None
    elif appointment_id is None and prescription_id is None:
        raise ValueError(
            "At least one of 'appointment_id' or 'prescription_id' must be provided."
        )
    elif appointment_id is not None and prescription_id is not None:
        raise ValueError("This url only supports one parameter with a non-null value.")

    # Now fetch the data according to the parameter value
    try:
        # Make the API request to fetch the data
        response = requests.get(api_url)
        data = response.json()
    except requests.exceptions.RequestException as e:
        # Handle any errors that occurred during the API request
        data = None
        error_message = str(e)

    # Render the template with the fetched data
    return render(
        request,
        "../templates/prescription_invoice.html",
        {"data": data, "error_message": error_message},
    )

    
# Convert "Sep 15 at 12:00 am" to %Y-%m-%d %H:%M:%S.%f' Format
def convert_string_date_django_datetime_format(input_date):

    # Define a mapping of month abbreviations to month numbers
    month_mapping = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
        'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
        'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }

    # Split the input string and extract date and time components
    parts = input_date.split()
    month = month_mapping[parts[0]]
    day = int(parts[1])
    time_parts = parts[3].split(':')
    hour = int(time_parts[0])
    minute = int(time_parts[1])

    # Create a datetime object with the extracted components
    formatted_date = datetime(datetime.now().year, month, day, hour, minute)

    # Format the datetime object into the desired output format
    output_format = timezone.datetime.strptime(str(formatted_date), '%Y-%m-%d %H:%M:%S')

    return output_format


def create_dummy_donation_history(self, limit):
    log_history = []
    count = 0
    while count < limit:
        # Get the current date
        current_date = datetime.now()
        # Calculate the first day and last day of the current month
        first_day_of_month = current_date.replace(day=1)
        last_day_of_month = (first_day_of_month + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        # Generate a random date within the current month
        random_date = first_day_of_month + timedelta(
            days=random.randint(0, (last_day_of_month - first_day_of_month).days))
        # Format the date as "YYYY-MM-DD"
        formatted_random_date = random_date.strftime("%Y-%m-%d")
        random_donation_amount = random.randrange(500, 10001, 500)
        log = {"date": formatted_random_date, "donation_amount": random_donation_amount}
        log_history.append(log)
        count += 1
    return log_history  




