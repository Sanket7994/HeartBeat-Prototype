
# This retrieves a Python logging instance (or creates it)
import logging
log = logging.getLogger(__name__)

import json
import requests
from rest_framework import status
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import *
from django.conf import settings
from .FakeData import dummy_prescription_data, dummy_appointment_data
from .helper_functions import DatetimeEncoder



# Uploading Fake appointment Data to db
class FakeDataGenerator(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, *args, **kwargs):
        try:
            fakeData = dummy_prescription_data
            response_data = []

            for fakeData in dummy_prescription_data[1:]:
                loaded_data = json.dumps(fakeData, cls=DatetimeEncoder)
                post_view_url = f"{settings.YOUR_DOMAIN}/clinic/scheduler/appointments/prescription/create/"
                headers = {"Content-Type": "application/json"}
                try:
                    response = requests.post(post_view_url, json=loaded_data, headers=headers)
                    response_data.append(response.json())
                except Exception as e:
                    log.error(str(e))
                    Response(str(e), status=status.HTTP_400_BAD_REQUEST)
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        except Exception as e:
            log.error(str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)