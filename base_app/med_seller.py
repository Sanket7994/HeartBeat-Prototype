# Imports
import time
import json
import stripe
import random
from math import ceil
import urllib.parse
from django.db import transaction
from django.conf import settings
from datetime import date, timedelta, datetime
from decimal import Decimal
from rest_framework import status
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import permissions
from django.http import JsonResponse
from django.http import HttpResponse
from rest_framework.views import APIView, View
from rest_framework.response import Response
from .seller_SETTINGS import STRIPE_SECRET_KEY
from .helper_functions import clean_payment_data, DecimalEncoder
from django.template.loader import render_to_string
from .models import PharmacyInventory, PurchaseOrder
from .serializer import PurchaseOrderSerializer, PharmacyInventorySerializer


# This retrieves a Python logging instance (or creates it)
import logging
log = logging.getLogger(__name__)

# fetch selling projects
stripe.api_key = STRIPE_SECRET_KEY


# Verifying classification of drug products
def verify_drug_class(input_string):
    pharmacy_inventory_instance = PharmacyInventory()
    choice_list = pharmacy_inventory_instance.get_drug_class_choices()
    found_choice = None
    for description, choice_key in choice_list:
        if choice_key == input_string:
            found_choice = description
    if found_choice:
        return found_choice
    else:
        return PharmacyInventory.GeneralDrugClass.OTHER


# Generate random manufacturing date of products within 2 month range
def generate_random_manufacturing_date():
    # Get the current date
    current_date = datetime.now()
    # Calculate the starting date for the last two months
    two_months_ago = current_date - timedelta(days=60)
    # Generate a random date within the last two months
    random_date = two_months_ago + timedelta(days=random.randint(0, 59))
    # Format the date as "YYYY-MM-DD"
    manufacturing_date = random_date.strftime("%Y-%m-%d")
    return manufacturing_date


# Extract individual product and price information from stripe api response
def extract_product_data(product):
    drug_name = product["name"]
    seller_stripe_product_id = product["id"]
    drug_description = product["description"]
    drug_image_url = product["images"][0]
    generic_name = product["metadata"]["Generic Name"]
    brand_name = product["metadata"]["Brand Name"]
    drug_class = product["metadata"]["Drug Class"]
    dosage_form = product["metadata"]["Dosage Form"]
    manufacture_date = generate_random_manufacturing_date()
    lifetime_in_months = product["metadata"]["Lifetime"]
    seller_stripe_price_id = product["default_price"]
    # Now collecting price information
    price_queryset = stripe.Price.retrieve(seller_stripe_price_id)
    unit_amount = price_queryset["unit_amount"]
    # Now collecting final data
    queryset = {
        "drug_name": drug_name,
        "drug_id": seller_stripe_product_id,
        "drug_image_url": drug_image_url,
        "drug_description": drug_description,
        "generic_name": generic_name,
        "brand_name": brand_name,
        "unit_type": "SINGLE_UNIT",
        "drug_class": verify_drug_class(drug_class.upper()),
        "dosage_form": dosage_form.upper(),
        "manufacture_date": manufacture_date,
        "lifetime_in_months": lifetime_in_months,
        "price": Decimal(int(unit_amount) / 100).quantize(Decimal("0.00")),
    }
    return queryset


# Now collecting price information
def fetch_stripe_price_id(stripe_product_id):
    try:
        # Checking seller's stripe db for product price id
        stripe.api_key = STRIPE_SECRET_KEY
        queryset = stripe.Product.retrieve(stripe_product_id)
        price_id = queryset["default_price"]
        return price_id
    
    except stripe.error.InvalidRequestError as e:
        try:
            # Fetch hospital inventory to check if product exists there
            stripe.api_key = settings.STRIPE_SECRET_KEY
            queryset = stripe.Product.retrieve(stripe_product_id)
            price_id = queryset["default_price"]
            return price_id
        except stripe.error.InvalidRequestError as e2:
            product_data = PharmacyInventory.objects.filter(drug_id=stripe_product_id).values().first()
            if product_data and product_data["stripe_price_id"]:
                price_id = product_data["stripe_price_id"]
                return price_id
            else:
                error_code = str(e2)
                return Response({"error": error_code}, status=status.HTTP_404_NOT_FOUND)
        except ValueError as v2:
                error_code = str(v2)
                return Response({"error": error_code}, status=status.HTTP_404_NOT_FOUND)
    except ValueError as v1:
        error_code = str(v1)
        return Response({"error": error_code}, status=status.HTTP_404_NOT_FOUND)

        
# Extract product and price information from stripe api response
def filter_product_array(data):
    final_data = []
    for product in data:
        seller_stripe_product_id = product["id"]
        drug_name = product["name"]
        drug_description = product["description"]
        drug_image_url = product["images"][0]
        generic_name = product["metadata"]["Generic Name"]
        brand_name = product["metadata"]["Brand Name"]
        drug_class = product["metadata"]["Drug Class"]
        dosage_form = product["metadata"]["Dosage Form"]
        manufacture_date = generate_random_manufacturing_date()
        lifetime_in_months = product["metadata"]["Lifetime"]
        seller_stripe_price_id = product["default_price"]
        price_data = []

        # Now collecting price information
        price_queryset = stripe.Price.retrieve(seller_stripe_price_id)
        currency = price_queryset["currency"]
        unit_amount = price_queryset["unit_amount"]

        element_data = {
            "currency": currency,
            "unit_amount": Decimal(int(unit_amount) / 100).quantize(Decimal("0.00")),
        }
        price_data.append(element_data)
        # Now collecting final data
        data = {
            "seller_stripe_product_id": seller_stripe_product_id,
            "drug_name": drug_name,
            "drug_description": drug_description,
            "drug_image_url": drug_image_url,
            "generic_name": generic_name,
            "brand_name": brand_name,
            "drug_class": drug_class,
            "dosage_form": dosage_form,
            "manufacture_date": manufacture_date,
            "lifetime_in_months": lifetime_in_months,
            "price": price_data,
            "seller_stripe_price_id": seller_stripe_price_id,
        }
        final_data.append(data)
    return final_data


# Function which creates a payment link from stripe
def create_PO_payment_link(po_data, return_items=False):
    try:
        order_data = json.loads(po_data["order"])
        # fetch selling projects
        stripe.api_key = STRIPE_SECRET_KEY

        line_items = []
        for product in order_data:
            product_id = str(product["drugId"])
            data = {
                "price": fetch_stripe_price_id(product_id),
                "quantity": int(product["quantity"]),
            }
            line_items.append(data)

        payment_link_payload = stripe.PaymentLink.create(line_items=line_items)
        payment_url = payment_link_payload["url"]

        if return_items == "line_items":
            return line_items
        elif return_items == "payment_url":
            return payment_url
    except stripe.error.InvalidRequestError as e:
        logging.error("Error related to Stripe: {}".format(str(e)))
        raise
    except Exception as ex:
        logging.error("Error unrelated to Stripe: {}".format(str(ex)))
        raise


# Seller Product view for site
class FetchProducts(APIView):
    stripe.api_key = STRIPE_SECRET_KEY
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            # Recording API runtime
            start_time = time.time()
            # Retrieve the current query param value from the request
            starting_after = self.request.GET.get("starting_after", None)
            page = int(self.request.GET.get("page", 1))
            limit = int(self.request.GET.get("limit", None))
            action = self.request.GET.get("action", None)

            # type error handling
            if limit == "None":
                limit = None
            if starting_after == "None":
                starting_after = None
            if action == "None":
                action = None

            # Increment or decrement the page parameter based on the request
            if action == "next":
                page += 1
            elif action == "previous":
                if page > 1:
                    page -= 1

            # Calculate total pages based on the count of products and the limit
            product_data = stripe.Product.list(limit=1000)
            total_records = len(product_data.data)
            total_pages = ceil(total_records / limit)

            # Fetch products from Stripe API using pagination parameters
            params = {"limit": limit, "starting_after": starting_after}
            products = stripe.Product.list(**params)

            # Extract product information as list of products of length == limit
            extracted_data = filter_product_array(products.data)

            # Update 'starting_after' value based on the last product fetched
            if extracted_data:
                last_product = extracted_data[-1]
                starting_after = last_product["seller_stripe_product_id"]

            # Create a response dictionary containing fetched data and pagination information
            response_data = {
                "data": extracted_data,
                "pagination": {
                    "page": page,
                    "total_pages": total_pages,
                    "total_records": total_records,
                    "has_more": products.has_more,
                    "starting_after": starting_after,
                },
            }

            # Record the end time
            end_time = time.time()
            fetch_time = round((end_time - start_time), 3)
            log.info(f"Fetched {len(extracted_data)} records in {fetch_time} seconds")

            return Response(response_data, status=status.HTTP_200_OK)
        except stripe.error.APIConnectionError as e:
            log.error(e)
            return Response(
                data={"Stripe error": str(e)}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            log.error(e)
            return Response(
                data={"Internal error": str(e)}, status=status.HTTP_400_BAD_REQUEST
            )


# Sellers point for checkout session
class PurchaseOrderCheckoutSession(APIView):
    stripe.api_key = STRIPE_SECRET_KEY
    permission_classes = [permissions.AllowAny]

    def post(self, request, purchase_order_id, *args, **kwargs):
        # Fetch the data related to the unique PO
        po_data = (PurchaseOrder.objects.filter(purchase_order_id=purchase_order_id).values().first())
        log.info("Custom Data with PID %s generated", purchase_order_id)
        
        if po_data["authorized_by"] != "NA" and po_data["payment_status"] == "PAID":
            forbidden_operation = {"message": "Payment for this PO has already been done"}
            return Response(forbidden_operation, status=status.HTTP_403_FORBIDDEN,)
        
        if po_data["authorized_by"] == "NA":
            forbidden_operation = {"message": "PO has not been approved yet."}
            return Response(forbidden_operation, status=status.HTTP_403_FORBIDDEN,)
        
        try:
            # Generate the line items for the checkout session
            items = create_PO_payment_link(po_data, return_items="line_items")
            log.info("Line items gathered")

            customer_id = settings.STRIPE_CUSTOMER_ID
            # Create or retrieve the Stripe customer
            customer_data = stripe.Customer.retrieve(customer_id)
            
            if customer_data is not None:
                # Create a checkout session with Stripe
                success_url = f"{settings.YOUR_DOMAIN}/{urllib.parse.quote(purchase_order_id)}/payment/success?session_id={{CHECKOUT_SESSION_ID}}"
                cancel_url = f"{settings.YOUR_DOMAIN}/{urllib.parse.quote(purchase_order_id)}/payment/cancel"
                
                checkout_session = stripe.checkout.Session.create(
                    success_url=success_url,
                    cancel_url=cancel_url,
                    customer=customer_id,
                    payment_method_types=["card"],
                    mode="payment",
                    line_items=items,
                    client_reference_id=customer_id,
                    currency="usd",
                )
                log.info("Checkout session created successfully")
                # Generate the payment link from Stripe
                payment_url = checkout_session.url

                # PayLink sanity Check
                if payment_url is None:
                    log.critical("Failed to create a payment link")
                    return Response(
                        data={"error": "Failed to create a payment link"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                log.info("Payment link created successfully")
                log.critical(f"New Checkout session created: {checkout_session.id}")
                payload = {
                    "payment_link": payment_url,
                    "checkout_session_id": checkout_session.id,
                }
                request.session["purchase_order_id"] = purchase_order_id
                return Response(payload, status=200)
            return Response({"Error": "Invalid Stripe Customer Id provided. Contact Seller."}, status=status.HTTP_403_FORBIDDEN,)
        # error handling
        except stripe.error.StripeError as e:
            log.error(str(e))
            return Response(data={"Stripe error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            log.error(str(e))
            return Response(data={"Internal error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR,)\
                
                
# Validate the Json response and update the data as per the request
def validate_json_ops(object, meta_data, encoder=None):
    if len(object) > 0:
            array = json.loads(object)
    else:
        array = []
    array.append(meta_data)
    return json.dumps(array, cls=encoder)


@transaction.atomic
def update_purchase_order_and_stock(request, purchase_order_id, cleaned_data):
    if purchase_order_id is None:
        return JsonResponse({"error": "Purchase order ID not provided"}, status=status.HTTP_400_BAD_REQUEST)
    try:
        purchase_order = PurchaseOrder.objects.select_for_update().get(purchase_order_id=purchase_order_id)
        status_data = {"payment_status": cleaned_data["stripe_payment_status"].upper()}
        PO_serializer = PurchaseOrderSerializer(purchase_order, data=status_data, partial=True)
        if PO_serializer.is_valid():
            purchase_order = PO_serializer.save()
            # Saving transaction details 
            purchase_order.transaction_data = validate_json_ops(purchase_order.transaction_data, 
                                                                cleaned_data, DecimalEncoder)
            # Adding a new thread  
            new_thread = {
                    "log": "Payment has been successfully done.",
                    "user_id": purchase_order.authorized_by,
                    "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                    }
            purchase_order.thread_history = validate_json_ops(purchase_order.thread_history, 
                                                              new_thread, None)
            # Saving the data to model
            purchase_order.save()
        else:
            return JsonResponse({"error": PO_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        order_data = json.loads(purchase_order.order)
        for product in order_data:
            try:
                drug_data = PharmacyInventory.objects.select_for_update().get(drug_name=product["drugName"])
                current_stock = drug_data.stock_available
                quantity_added = int(product["quantity"])
                new_stock = current_stock + quantity_added
                drug_data.stock_available = new_stock
                
                # Saving stock details 
                new_order = {
                    "quantity": quantity_added, 
                    "added_on": datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 
                    "purchase_order_id": purchase_order_id
                }
                drug_data.stock_history = validate_json_ops(drug_data.stock_history, new_order, None)
                drug_data.save()

            except ObjectDoesNotExist:
                return JsonResponse({"error": "Drug ID does not exist!"}, status=status.HTTP_400_BAD_REQUEST)
        
        context = {"retrieve_session_data": cleaned_data}
        return context
    
    except PurchaseOrder.DoesNotExist:
        return JsonResponse({"error": f"Purchase Order ID {purchase_order_id} does not exist!"}, status=status.HTTP_400_BAD_REQUEST)
    
    except stripe.error.StripeError as e:
        log.critical(f"error : {str(e)}")
        return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        log.error(f"error : {str(e)}")
        return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# Success View
class SuccessPOPaymentView(View):
    stripe.api_key = STRIPE_SECRET_KEY
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        session_id = request.GET.get("session_id")
        purchase_order_id = str((request.path).split("/")[1])
        
        try:
            session_data = stripe.checkout.Session.retrieve(session_id)
            log.info("Session Data retrieved")
            # Cleaning data
            cleaned_session_data = clean_payment_data(session_data)
            cleaned_data = {
                "Company_id": cleaned_session_data["client_reference_id"],
                "session_id": cleaned_session_data["id"],
                "payment_intent": cleaned_session_data["payment_intent"],
                "payment_amount": Decimal(int(cleaned_session_data["amount_total"])/100).quantize(Decimal('0.00')),
                "payment_method": cleaned_session_data["payment_method_types"][0],
                "client_billing_address": json.loads(json.dumps(cleaned_session_data["customer_details"]["address"])),
                "stripe_session_status": cleaned_session_data["status"],
                "stripe_payment_status": cleaned_session_data["payment_status"],
                "session_created_on": datetime.fromtimestamp(cleaned_session_data["created"]).strftime("%d-%m-%Y %H:%M:%S"),
                "session_expired_on": datetime.fromtimestamp(cleaned_session_data["expires_at"]).strftime("%d-%m-%Y %H:%M:%S"),}

            # Applying necessary updates
            context = update_purchase_order_and_stock(request, purchase_order_id, cleaned_data)
            
            # Render success payment page with Customer Satisfaction Feedback form
            html_content = render_to_string("po_success.html", context)
            log.info("Success payment page rendered")
            return HttpResponse(html_content, status=status.HTTP_200_OK)
        # Error handling
        except stripe.error.StripeError as e:
            error_message = str(e)
            log.error(f"error: {error_message}")
            context = {'error_message': error_message}
            html_content = render_to_string("po_cancel.html", context)
            return HttpResponse(html_content)

        except Exception as e:
            error_message = str(e)
            log.error(f"error: {error_message}")
            context = {'error_message': error_message}
            html_content = render_to_string("po_cancel.html", context)
            return HttpResponse(html_content)


# Cancel Response View
class CancelPOPaymentView(View):
    def get(self, request):
        stripe.api_key = STRIPE_SECRET_KEY
        html_content = render_to_string("po_cancel.html")
        return HttpResponse(html_content)
