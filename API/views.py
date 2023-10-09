from django.http import HttpResponse
from django.views import View
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt


class DownloadPublicKeyView(View):
    @csrf_exempt
    def get(self, request, *args, **kwargs):
        with open('publickey.pem', 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/x-pem-file')
            response['Content-Disposition'] = 'inline;filename=publickey.pem'
        return response
@csrf_exempt
def APIRequest(request):
    # Handle API requests here
    return HttpResponse('API Request received')
