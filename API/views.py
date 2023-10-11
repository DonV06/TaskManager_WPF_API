
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from django.http import HttpResponse, JsonResponse
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
        if (SendedJson["type"] == "loginNOTOKEN"): return loginNOTOKEN(SendedJson)
        if (SendedJson["type"] == "loginTOKEN"): return loginTOKEN(SendedJson)
    return HttpResponse('API Request received')

def loginTOKEN(SendedJson):
    TokenEncrypted = SendedJson["token"]
    print(TokenEncrypted)
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
    AesKey = private_key.decrypt(AesKeyRsaOnly, padding.PKCS1v15())
    AesKeyIV = private_key.decrypt(AesKeyIVRsaOnly, padding.PKCS1v15())
    cipher = Cipher(algorithms.AES(AesKey), modes.CBC(AesKeyIV), backend=default_backend())
    Decryptor = cipher.decryptor()
    TokenRSAonly = base64.b64decode(TokenEncrypted)
    TokenDecrypted = Decryptor.update(TokenRSAonly).decode().strip()

    try:
        models.User.objects.get(token=TokenDecrypted)
    except models.User.DoesNotExist:
        return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    return JsonResponse({'status': 200})
def loginNOTOKEN(SendedJson):
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
    AesKey = private_key.decrypt(AesKeyRsaOnly, padding.PKCS1v15())
    AesKeyIV = private_key.decrypt(AesKeyIVRsaOnly, padding.PKCS1v15())
    cipher = Cipher(algorithms.AES(AesKey), modes.CBC(AesKeyIV), backend=default_backend())
    Decryptor = cipher.decryptor()
    LoginDecrypted = Decryptor.update(LoginEncrypted)
    Decryptor = cipher.decryptor()
    PasswordDecrypted = Decryptor.update(PasswordEncrypted)

    try:
        userselected = models.User.objects.get(login=LoginDecrypted.decode().strip())
    except models.User.DoesNotExist:
        return JsonResponse({'status': 201, 'errormessage': f"Account don't exists!"})

    if (userselected.password != PasswordDecrypted.decode().strip()): return JsonResponse(
        {'status': 202, 'errormessage': "Password not correct!"})
    userselected.AESkey = str(base64.b64encode(AesKey).decode())
    userselected.AESkeyIV = str(base64.b64encode(AesKeyIV).decode())
    useruuid = str(uuid.uuid4())
    userselected.token = useruuid
    userselected.save()

    encryptor = cipher.encryptor()
    block_size = 16  # AES block size is 16 bytes
    padding_length = block_size - len(useruuid) % block_size
    plaintext_padded = useruuid + chr(padding_length) * padding_length

    useruuidEncrypted = encryptor.update(plaintext_padded.encode('utf-8')) + encryptor.finalize()
    useruuid = base64.b64encode(useruuidEncrypted)
    returndata = {'status': 200, 'token': useruuid.decode()}

    return JsonResponse(returndata)