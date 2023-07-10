# Filter and search for views

def filter_queryset(queryset, filter_fields):
    for field, value in filter_fields.items():
        if value:
            queryset = queryset.filter(**{field: value})
    return queryset



