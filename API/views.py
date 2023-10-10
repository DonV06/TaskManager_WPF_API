
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from django.http import HttpResponse
from django.views import View
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
import base64, json, uuid
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

        SendedJson = json.loads(request.body.decode('utf-8'))
        LoginEncrypted = base64.b64decode(SendedJson["User"])
        PasswordEncrypted = base64.b64decode(SendedJson["Password"])
        AesKeyEncrypted = SendedJson["aeskey"].split("|")[0]
        AesKeyIVEncrypted = SendedJson["aeskey"].split("|")[1]

        with open('privatekey.pem', 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        AesKeyIVRsaOnly = base64.b64decode(AesKeyIVEncrypted)
        AesKeyRsaOnly = base64.b64decode(AesKeyEncrypted)
        # Decrypt the ciphertext
        AesKey = private_key.decrypt(AesKeyRsaOnly,padding.PKCS1v15())
        AesKeyIV = private_key.decrypt(AesKeyIVEncrypted, padding.PKCS1v15())
        cipher = Cipher(algorithms.AES(AesKey),modes.CBC(AesKeyIVEncrypted),backend=default_backend())
        Decryptor = cipher.decryptor()
        LoginDecrypted = Decryptor.update(LoginEncrypted)
        Decryptor = cipher.decryptor()
        PasswordDecrypted = Decryptor.update(PasswordEncrypted)
        try:
            userselected = models.User.objects.get(login=LoginDecrypted.decode().strip())
        except models.User.DoesNotExist:
            return HttpResponse(f"Account don't exists!")

        if (userselected.password != PasswordDecrypted.decode().strip()): return HttpResponse("Password not correct!")
        userselected.AESkey = base64.b64encode(AesKey)
        useruuid = uuid.uuid4()
        userselected.token = useruuid
        userselected.save()
        return HttpResponse(f"Token: '{useruuid}'")
    return HttpResponse('API Request received')
