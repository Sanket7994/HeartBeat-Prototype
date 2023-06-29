# IMPORTS
import stripe, logging
from django.db.models import F
from django.conf import settings
from .views import (
    Clinic,
    ClinicMember,
    PatientAppointment,
    MedicalProceduresTypes,
    PrescribedMedicationModel,
    Prescription,
)


def fetch_prescription_data(appointment_id=None, prescription_id=None):
    # Creating empty dictionaries
    collection_dict = {}

    # Selected necessary Keys only
    # keys = [
    #     "prescription_id",
    #     "stripe_appointment_service_id",
    #     "stripe_appointment_price_id",
    #     "appointment_fee",
    #     "med_bill_amount",
    #     "coupon_discount",
    #     "grand_total",
    #     "description",
    #     "payment_status",
    #     "approval_status",
    #     "created_at",
    #     "prescribed_meds",
    #     "appointment_id",
    #     "patient_first_name",
    #     "patient_first_name",
    #     "patient_last_name",
    #     "patient_gender",
    #     "date_of_birth",
    #     "patient_age",
    #     "patient_email",
    #     "patient_contact_number",
    #     "recurring_patient",
    #     "appointment_date",
    #     "appointment_slot",
    #     "appointment_status",
    #     "selected_procedures",
    #     "staff_first_name",
    #     "staff_last_name",
    #     "staff_designation",
    #     "staff_email",
    #     "staff_contact_number",
    #     "clinic_name",
    #     "clinic_logo",
    #     "clinic_contact_number",
    #     "clinic_address",
    #     "clinic_city",
    #     "clinic_zipcode",
    #     "clinic_country",
    #     "clinic_email",
    # ]

    if appointment_id is not None:
        # Fetch appointment data
        appointment = (
            PatientAppointment.objects.filter(appointment_id=appointment_id)
            .values()
            .first()
        )

        if appointment is not None:
            # Initialize nested dictionary for the appointment
            collection_dict[appointment_id] = {
                "appointment": appointment,
                "selected_procedures": [],
                "prescriptions": [],
            }

            # Fetch selected procedures
            selected_procedures = MedicalProceduresTypes.objects.filter(
                patientappointment=appointment_id
            ).values()
            collection_dict[appointment_id]["selected_procedures"] = list(
                selected_procedures
            )

            # Fetch prescriptions associated with the appointment
            prescriptions = Prescription.objects.filter(
                appointment_id=appointment_id
            ).values()
            for prescription in prescriptions:
                prescription_id = prescription["prescription_id"]
                prescribed_meds = PrescribedMedicationModel.objects.filter(
                    for_prescription_id=prescription_id
                ).values()

                # Add prescription and prescribed meds to the nested dictionary
                collection_dict[appointment_id]["prescriptions"].append(
                    {
                        "prescription": prescription,
                        "prescribed_meds": list(prescribed_meds),
                    }
                )

                # Fetch staff and clinic data
                staff_id = appointment["relatedRecipient_id"]
                staff = (
                    ClinicMember.objects.filter(staff_id=str(staff_id)).values().first()
                )
                clinic_id = staff["clinic_name_id"]
                clinic = (
                    Clinic.objects.filter(clinic_id=str(clinic_id)).values().first()
                )

                # Add staff and clinic data to the nested dictionary
                collection_dict[appointment_id]["prescriptions"][-1]["staff"] = staff
                collection_dict[appointment_id]["prescriptions"][-1]["clinic"] = clinic

    # if prescription_id is not None:
    #     prescription = (
    #         Prescription.objects.filter(prescription_id=prescription_id)
    #         .values()
    #         .first()
    #     )
    #     if prescription is not None:
    #         appointment_id = prescription["appointment_id_id"]
    #         if appointment_id is not None:
    #             appointment = (
    #                 PatientAppointment.objects.filter(appointment_id=appointment_id)
    #                 .values()
    #                 .first()
    #             )
    #             consultant = (
    #                 ClinicMember.objects.filter(
    #                     staff_id=appointment["relatedRecipient_id"]
    #                 )
    #                 .values()
    #                 .first()
    #             )
    #             clinic = (
    #                 Clinic.objects.filter(clinic_id=consultant["clinic_name_id"])
    #                 .values()
    #                 .first()
    #             )
    #             if appointment is not None:
    #                 if "selected_procedures" not in collection_dict:
    #                     selected_procedures = MedicalProceduresTypes.objects.filter(
    #                         patientappointment=appointment_id
    #                     ).values()
    #                     collection_dict["selected_procedures"] = selected_procedures

    #                 if "appointment_id" not in collection_dict:
    #                     collection_dict.update(appointment)
    #                     collection_dict.update(consultant)
    #                     collection_dict.update(clinic)

    #                 if "prescription_id" not in collection_dict:
    #                     collection_dict.update(prescription)

    #                 prescribed_meds = (
    #                     PrescribedMedicationModel.objects.filter(
    #                         for_prescription_id=prescription_id
    #                     )
    #                     .annotate(
    #                         medicine_name=F("medicine__drug_name"),
    #                         medicine_purpose=F("medicine__drug_class"),
    #                         stripe_medicine_id=F("medicine__stripe_product_id"),
    #                         stripe_price_id=F("medicine__stripe_price_id"),
    #                     )
    #                     .values()
    #                 )
    #                 if "prescribed_meds" not in collection_dict:
    #                     collection_dict["prescribed_meds"] = prescribed_meds

    # if keys is not None:
    #     collection_dict = {
    #         key: collection_dict[key] for key in keys if key in collection_dict
    #     }

    return collection_dict


# Function which creates a payment link from stripe
def create_payment_link(prescription_dict, return_items=False):
    try:
        stripe.api_key = settings.STRIPE_SECRET_KEY

        line_items = [
            {
                "price": str(med_data["stripe_price_id"]),
                "quantity": int(med_data["quantity"]),
            }
            for med_data in prescription_dict["prescribed_meds"]
        ]

        line_items.append(
            {
                "price": str(prescription_dict.get("stripe_appointment_price_id", "")),
                "quantity": 1,
            }
        )
        payment_link_payload = stripe.PaymentLink.create(line_items=line_items)
        payment_url = payment_link_payload["url"]

        if return_items == "line_items":
            return line_items
        elif return_items == "payment_url":
            return payment_url

    except stripe.error.CardError as e:
        logging.error("A payment error occurred: {}".format(e.user_message))
        raise
    except stripe.error.InvalidRequestError:
        logging.error("An invalid request occurred.")
        raise
    except Exception as ex:
        logging.error("Error unrelated to Stripe: {}".format(str(ex)))
        raise
