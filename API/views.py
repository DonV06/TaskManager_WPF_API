from cryptography.hazmat.backends.openssl import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from django.http import HttpResponse
from django.views import View
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
import json

import base64
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives import serialization, asymmetric, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

from API import models


class DownloadPublicKeyView(View):
    @csrf_exempt
    def get(self, request, *args, **kwargs):
        with open('publickey.pem', 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/x-pem-file')
            response['Content-Disposition'] = 'inline;filename=publickey.pem'
        return response
@csrf_exempt
def APIRequest(request):
    if request.method == 'POST':
        # Load the JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))
        login = base64.b64decode(data["User"])
        password = base64.b64decode(data["Password"])
        AesKey = data["aeskey"].split("|")[0]
        AesKeyIV = data["aeskey"].split("|")[1]

        # Load the private key from a PEM file
        with open('privatekey.pem', 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Base64-encoded ciphertext from C#
        AesKeyIV = base64.b64decode(AesKeyIV)
        # Decode the base64 ciphertext to bytes
        ciphertext = base64.b64decode(AesKey)
        print(ciphertext)
        # Decrypt the ciphertext
        plaintext = private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        )

        AesKeyIV = private_key.decrypt(AesKeyIV, padding.PKCS1v15())
        print(AesKeyIV)
        # Convert the decrypted bytes to string (assuming the plaintext was UTF-8 encoded)
        cipher = Cipher(
            algorithms.AES(plaintext),
            modes.CBC(AesKeyIV),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        login = decryptor.update(login)
        decryptor = cipher.decryptor()
        password = decryptor.update(password)
        print(login.decode().strip())
        try:
            userselected = models.User.objects.get(login=login.decode().strip())
        except models.User.DoesNotExist:
            return HttpResponse(f"Account don't exists!")

        if (userselected.password != password.decode().strip()): return HttpResponse("Password not correct!")
        userselected.AESkey = base64.b64encode(plaintext)
        import uuid
        useruuid = uuid.uuid4()
        userselected.token = useruuid
        userselected.save()
        return HttpResponse(f"Token: '{useruuid}'")
    # Handle API requests here
    return HttpResponse('API Request received')
