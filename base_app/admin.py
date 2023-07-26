from django.contrib import admin
from .models import CustomUser, Clinic, ClinicMember, ClientDataCollectionPool, Prescription, PharmacyInventory
from .models import MedicalProceduresTypes, PatientAppointment, ClientDataCollectionPool
from .models import ClientServiceFeedback, PurchaseOrder, TaskAssignmentManager

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(Clinic)
admin.site.register(ClinicMember)
admin.site.register(TaskAssignmentManager)
admin.site.register(MedicalProceduresTypes)
admin.site.register(PatientAppointment)
admin.site.register(ClientDataCollectionPool)
admin.site.register(PharmacyInventory)
admin.site.register(PurchaseOrder)
admin.site.register(Prescription)
admin.site.register(ClientServiceFeedback)


