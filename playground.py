{
    "id": "prod_OSbUWaUrInEQPj",
    "object": "product",
    "active": true,
    "attributes": [],
    "created": 1692179097,
    "default_price": "price_1NfgHfSJAD3uXCYoJqKaBPaD",
    "description": "Smoking cessation aid in paan flavor, providing a nicotine substitute to manage cravings.",
    "images": [
        "https://files.stripe.com/links/MDB8YWNjdF8xTmZlWkxTSkFEM3VYQ1lvfGZsX3Rlc3RfSk4yM1NvSnpseUZRa0JSbjJpbFFBamFX002kvaoQBV"
    ],
    "livemode": false,
    "metadata": {
        "Brand Name": "Cipla",
        "Dosage Form": "Oral",
        "Drug Class": "Analgesics",
        "Generic Name": "Nicotine polacrilex",
        "Lifetime": "24",
    },
    "name": "Nicotex 2mg Chew Gum - Paan Flavour 9's",
    "package_dimensions": null,
    "shippable": null,
    "statement_descriptor": null,
    "tax_code": null,
    "type": "service",
    "unit_label": null,
    "updated": 1692184292,
    "url": null,
}


{
    "active": true,
    "billing_scheme": "per_unit",
    "created": 1692179099,
    "currency": "usd",
    "custom_unit_amount": null,
    "id": "price_1NfgHfSJAD3uXCYoJqKaBPaD",
    "livemode": false,
    "lookup_key": null,
    "metadata": {},
    "nickname": null,
    "object": "price",
    "product": "prod_OSbUWaUrInEQPj",
    "recurring": null,
    "tax_behavior": "unspecified",
    "tiers_mode": null,
    "transform_quantity": null,
    "type": "one_time",
    "unit_amount": 299,
    "unit_amount_decimal": "299",
}


# Task Completed Today: 1) Updated frontend-code to fetch data from sellers stripe database 2) Added new js queries to function according to that 3) Updated Purchase Order model and views for the CRUD operations


{
    "thread_history": [
        {
            "log": "Revised Purchase Order sent for Approval",
            "timestamp": "18/08/2023, 12:32:19",
            "user_id": "CM-3A9E3304E4",
        }
    ],
    "order": [
        {"drugId": "prod_OSbUWaUrInEQPj", "quantity": "20"},
        {"drugId": "prod_OSbSNfk0GgQfhw", "quantity": "12"},
        {"drugId": "prod_OSbRyQgUWLW4rR", "quantity": "30"},
        {"drugId": "prod_OSbIhfi70UX0He", "quantity": "10"},
        {"drugId": "prod_OSbFTuygHvZLbN", "quantity": "20"},
    ],
    "approval_status": "PENDING",
    "authorized_by": "",
}


text_data: {
    "drug_id": "MED-1A620B1F5D",
    "added_at": "2023-08-21T06:41:14.795751Z",
    "stripe_product_id": "prod_OUQeUHJkDW6XFD",
    "drug_name": "Nestle Peptamen Peptide Based Diet Powder - Vanilla Flavour 400 gm (Tin)",
    "drug_image_url": "https://files.stripe.com/links/MDB8YWNjdF8xTmZlWkxTSkFEM3VYQ1lvfGZsX3Rlc3RfT3UwbGJIbkNWSVEybUpoYW1uc1ZDTVRG00YaHd7Z9p",
    "drug_image": "/media/default_image.png",
    "generic_name": "Peptide Based Diet Powder",
    "brand_name": "Nestle",
    "drug_class": "Other",
    "dosage_form": "ORAL",
    "unit_type": "SINGLE_UNIT",
    "price": "17.49",
    "stripe_price_id": "price_1NhRnaSFXVKGwTOETl4fcXR2",
    "add_new_stock": 0,
    "stock_available": 0,
    "stock_history": {"added_on": "", "quantity": "", "purchase_order_id": ""},
    "manufacture_date": "2023-08-10",
    "lifetime_in_months": 2,
    "expiry_date": "2023-10-09",
}


content_data: b'{"drug_id":"MED-1A620B1F5D","added_at":"2023-08-21T06:41:14.795751Z","stripe_product_id":"prod_OUQeUHJkDW6XFD","drug_name":"Nestle Peptamen Peptide Based Diet Powder - Vanilla Flavour 400 gm (Tin)","drug_image_url":"https://files.stripe.com/links/MDB8YWNjdF8xTmZlWkxTSkFEM3VYQ1lvfGZsX3Rlc3RfT3UwbGJIbkNWSVEybUpoYW1uc1ZDTVRG00YaHd7Z9p","drug_image":"/media/default_image.png","generic_name":"Peptide Based Diet Powder","brand_name":"Nestle","drug_class":"Other","dosage_form":"ORAL","unit_type":"SINGLE_UNIT","price":"17.49","stripe_price_id":"price_1NhRnaSFXVKGwTOETl4fcXR2","add_new_stock":0,"stock_available":0,"stock_history":{"added_on":"","quantity":"","purchase_order_id":""},"manufacture_date":"2023-08-10","lifetime_in_months":2,"expiry_date":"2023-10-09"}'


{
    "after_expiration": null,
    "allow_promotion_codes": null,
    "amount_subtotal": 71088,
    "amount_total": 71088,
    "automatic_tax": {"enabled": false, "status": null},
    "billing_address_collection": "required",
    "cancel_url": "http://127.0.0.1:8000/payment/cancel",
    "client_reference_id": "cus_OSbaOsr6TQclT2",
    "consent": null,
    "consent_collection": null,
    "created": 1692769627,
    "currency": "usd",
    "currency_conversion": null,
    "custom_fields": [],
    "custom_text": {"shipping_address": null, "submit": null},
    "customer": "cus_OSbaOsr6TQclT2",
    "customer_creation": null,
    "customer_details": {
        "address": null,
        "email": "sanket.chouriya@oodles.io",
        "name": null,
        "phone": null,
        "tax_exempt": "none",
        "tax_ids": null,
    },
    "customer_email": null,
    "expires_at": 1692856027,
    "id": "cs_test_b17ldTXfncVvTvACkxMypeV9w8289X4kom5mPt282DXFsB61ZycuGJmENl",
    "invoice": null,
    "invoice_creation": {
        "enabled": false,
        "invoice_data": {
            "account_tax_ids": null,
            "custom_fields": null,
            "description": null,
            "footer": null,
            "metadata": {},
            "rendering_options": null,
        },
    },
    "livemode": false,
    "locale": null,
    "metadata": {},
    "mode": "payment",
    "object": "checkout.session",
    "payment_intent": null,
    "payment_link": null,
    "payment_method_collection": "always",
    "payment_method_options": {},
    "payment_method_types": ["card"],
    "payment_status": "unpaid",
    "phone_number_collection": {"enabled": false},
    "recovered_from": null,
    "setup_intent": null,
    "shipping_address_collection": null,
    "shipping_cost": null,
    "shipping_details": null,
    "shipping_options": [],
    "status": "open",
    "submit_type": null,
    "subscription": null,
    "success_url": "http://127.0.0.1:8000/payment/success?session_id={CHECKOUT_SESSION_ID}",
    "total_details": {"amount_discount": 0, "amount_shipping": 0, "amount_tax": 0},
    "url": "https://checkout.stripe.com/c/pay/cs_test_b17ldTXfncVvTvACkxMypeV9w8289X4kom5mPt282DXFsB61ZycuGJmENl#fidkdWxOYHwnPyd1blpxYHZxWjA0S2NgX0lWT0RBNnBdRlxqMmdxdmZVc2J%2FNz0wNFNKTDxBZ39fcXdgXVQ8VGZPbkpxb09hXGJAVmdnR01nV2RqPF1iVX9IcHQyUXcxSVRMSTUxdGxmQ0tLNTVMdVVxVWpHTScpJ2N3amhWYHdzYHcnP3F3cGApJ2lkfGpwcVF8dWAnPydocGlxbFpscWBoJyknYGtkZ2lgVWlkZmBtamlhYHd2Jz9xd3BgeCUl",
}


{
    "created_by": "SA-90CAE04A68",
    "thread_history": [
        {
            "log": "Added prod_OVGaBRh6Yj8iP8 to PO List",
            "timestamp": "24/08/2023, 11:09:56",
            "user_id": "SA-90CAE04A68",
        },
        {
            "log": "Revised Purchase Order sent for Approval",
            "timestamp": "24/08/2023, 11:09:58",
            "user_id": "SA-90CAE04A68",
        },
    ],
    "order": [
        {
            "drugId": "MED-6DAD2B70EA",
            "drugName": "Ciprofloxacin Hydrochloride & Tinidazole Tablets",
            "quantity": "50",
            "pricePerUnit": "3.49",
        },
        {
            "drugId": "MED-1B4E6935A4",
            "drugName": "Ketorolac Tromethamine 10 mg Dispersible Tablet",
            "quantity": "50",
            "pricePerUnit": "2.99",
        },
        {
            "drugId": "MED-9155B1E2EF",
            "drugName": "Omeprazole 20 mg Capsules",
            "quantity": "50",
            "pricePerUnit": "8.99",
        },
        {
            "drugId": "MED-9AC95AF6B2",
            "drugName": "Diclofenac-Potassium Paracetamol Chlorzoxazone 250mg Tablet",
            "quantity": "100",
            "pricePerUnit": "5.99",
        },
        {
            "drugId": "prod_OVGaBRh6Yj8iP8",
            "drugName": "INLIFE Diastan Plus Diabetic Care Powder 300 gm",
            "quantity": "20",
            "pricePerUnit": "19.99",
        },
    ],
    "approval_status": "PENDING",
    "authorized_by": "NA",
}
