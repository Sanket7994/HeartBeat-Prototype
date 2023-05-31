from rest_framework import status
from rest_framework.response import Response
from django.core.paginator import Paginator, EmptyPage


# function which takes input data and applies pagination as per request
def paginate_data(queryset, serializer, load_quantity, request):
    paginator = Paginator(queryset, load_quantity)
    page_number = request.data.get("page")

    page_obj = paginator.get_page(page_number)
    serialized_data = serializer(page_obj.object_list, many=True)

    # result dictionary
    payload = {
        "Page": {
            "totalRecords": len(queryset),
            "current": page_obj.number,
            "next": page_obj.has_next(),
            "previous": page_obj.has_previous(),
            "totalPages": page_obj.paginator.num_pages,
        },
        "Result": serialized_data.data,
    }

    return Response(
        payload,
        status=status.HTTP_200_OK,
    )
