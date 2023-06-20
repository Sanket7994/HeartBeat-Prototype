from rest_framework import pagination
from rest_framework import serializers
from rest_framework.exceptions import NotFound
from rest_framework import status

class CustomPagination(pagination.LimitOffsetPagination):
    default_limit = 5
    max_limit = 100
    min_limit = 1
    min_offset = 0
    max_offset = 50

    def paginate_queryset(self, queryset, request, view=None):
        limit = self.get_limit(request)
        offset = self.get_offset(request)
        page = self.get_page(request)

        self.validate_limit(limit)
        self.validate_offset(offset)

        total_items = self.get_total_items(queryset)

        if page is not None:
            if page < 1:
                page = 1
                raise NotFound(detail="Error 404: Page Not Found!", code=status.HTTP_404_NOT_FOUND)

            total_pages = self.calculate_total_pages(total_items, limit)
            if page > total_pages:
                raise serializers.ValidationError({
                    "page": ["Invalid page number. There are only {} pages.".format(total_pages)]
                })

            offset = self.get_page_offset(page, limit)
        return super().paginate_queryset(queryset, request, view)

    def get_limit(self, request):
        limit = request.query_params.get('limit', self.default_limit)
        return int(limit)

    def get_offset(self, request):
        offset = request.query_params.get('offset', self.min_offset)
        return int(offset)

    def get_page(self, request):
        page = request.query_params.get('page')
        if page is not None:
            try:
                return int(page)
            except ValueError:
                pass
        return None

    def get_page_offset(self, page, limit):
        if page < 1:
            page = 1
        return (page - 1) * limit

    def validate_limit(self, limit):
        if limit > self.max_limit:
            raise serializers.ValidationError({
                "limit": ["Limit should be less than or equal to {0}".format(self.max_limit)]
            })
        elif limit < self.min_limit:
            raise serializers.ValidationError({
                "limit": ["Limit should be greater than or equal to {0}".format(self.min_limit)]
            })

    def validate_offset(self, offset):
        if offset > self.max_offset:
            raise serializers.ValidationError({
                "offset": ["Offset should be less than or equal to {0}".format(self.max_offset)]
            })
        elif offset < self.min_offset:
            raise serializers.ValidationError({
                "offset": ["Offset should be greater than or equal to {0}".format(self.min_offset)]
            })

    def get_total_items(self, queryset):
        return queryset.count()

    def calculate_total_pages(self, total_items, limit):
        return (total_items + limit - 1) // limit
