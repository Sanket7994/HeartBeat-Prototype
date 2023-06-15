from django.contrib import admin
from .models import CustomUser, Clinic, ClinicMember
from .models import PatientAppointment, PatientAppointment

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(Clinic)
admin.site.register(ClinicMember)
admin.site.register(PatientAppointment)



