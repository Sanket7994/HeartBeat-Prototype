from rest_framework import permissions


# Custom Permission for Site Administration
class IsSiteAdmin(permissions.IsAuthenticated):
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        user = request.user
        return getattr(user, 'is_site_admin', False)
    
# Custom Permission for Clinic Management
class IsClinicManagement(permissions.IsAuthenticated):
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        user = request.user
        return getattr(user, 'is_site_admin', False)