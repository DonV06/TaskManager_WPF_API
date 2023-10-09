from django.http import HttpResponse
from django.views import View
from django.shortcuts import render

class DownloadPublicKeyView(View):
    def get(self, request, *args, **kwargs):
        with open('publickey.pem', 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/x-pem-file')
            response['Content-Disposition'] = 'inline;filename=publickey.pem'
        return response

class APIRequestView(View):
    def post(self, request, *args, **kwargs):
        # Handle API requests here
        return HttpResponse('API Request received')
