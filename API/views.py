
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


def decryptAES(message, AEScipher):
    with open('privatekey.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    messageAES = base64.b64decode(message)
    Decryptor = AEScipher.decryptor()
    return Decryptor.update(messageAES).decode().strip()


@csrf_exempt
def APIRequest(request):
    if request.method == 'POST':

        SendedJson = json.loads(request.body.decode('utf-8'))
        if SendedJson["type"] == "loginNOTOKEN": return loginNOTOKEN(SendedJson)
        if SendedJson["type"] == "loginTOKEN": return loginTOKEN(SendedJson)
        if SendedJson["type"] == "addTask": return addTask(SendedJson)
        if SendedJson["type"] == "getTask": return getTask(SendedJson)
        if SendedJson["type"] == "refresh": return Refresh(SendedJson)
        if SendedJson["type"] =="delTask": return delTask(SendedJson)
    return HttpResponse('API Request received')

def loginTOKEN(SendedJson):
    TokenEncrypted = SendedJson["token"]
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
    AesKey = private_key.decrypt(AesKeyRsaOnly, padding.PKCS1v15())
    AesKeyIV = private_key.decrypt(AesKeyIVRsaOnly, padding.PKCS1v15())
    cipher = Cipher(algorithms.AES(AesKey), modes.CBC(AesKeyIV), backend=default_backend())


    TokenDecrypted = decryptAES(TokenEncrypted, cipher)

    try:
        userselected = models.User.objects.get(token=TokenDecrypted)
    except models.User.DoesNotExist:
        return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    userselected.AESkey = str(base64.b64encode(AesKey).decode())
    userselected.AESkeyIV = str(base64.b64encode(AesKeyIV).decode())
    userselected.save()
    return JsonResponse({'status': 200})

def Refresh(SendedJson):
    TokenEncrypted = SendedJson["token"]
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
    AesKey = private_key.decrypt(AesKeyRsaOnly, padding.PKCS1v15())
    AesKeyIV = private_key.decrypt(AesKeyIVRsaOnly, padding.PKCS1v15())
    cipher = Cipher(algorithms.AES(AesKey), modes.CBC(AesKeyIV), backend=default_backend())

    TokenDecrypted = decryptAES(TokenEncrypted, cipher)

    try:
        user = models.User.objects.get(token=TokenDecrypted)
    except models.User.DoesNotExist:
        return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})

    uuidstask = []
    tasks = models.Task.objects.filter(specifiedUser=user)
    returnstring = ""
    for _task in tasks:
        returnstring += (_task.uuid + "|")
    return JsonResponse({'status': 200, 'uuids': returnstring})
def getTask(SendedJson):
    TokenEncrypted = SendedJson["token"]
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
    AesKey = private_key.decrypt(AesKeyRsaOnly, padding.PKCS1v15())
    AesKeyIV = private_key.decrypt(AesKeyIVRsaOnly, padding.PKCS1v15())
    cipher = Cipher(algorithms.AES(AesKey), modes.CBC(AesKeyIV), backend=default_backend())

    TokenDecrypted = decryptAES(TokenEncrypted, cipher)

    try:
        user = models.User.objects.get(token=TokenDecrypted)
    except models.User.DoesNotExist:
        return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    taskUUIDEncrypted = SendedJson["taskUUID"]
    taskUUID = decryptAES(taskUUIDEncrypted, cipher)
    try:
        task = models.Task.objects.get(uuid = taskUUID)
    except models.Task.DoesNotExist:
        return JsonResponse({'status': 204, 'errormessage': f"Task Don't exists!"})
    nameTask = task.name
    encryptor = cipher.encryptor()
    block_size = 16  # AES block size is 16 bytes
    padding_length = block_size - len(nameTask) % block_size
    plaintext_padded = nameTask + chr(padding_length) * padding_length

    taskNameEncrypted = encryptor.update(plaintext_padded.encode('utf-8')) + encryptor.finalize()
    taskName = base64.b64encode(taskNameEncrypted).decode()
    return JsonResponse({'status': 200, 'nameTask': taskName})

def delTask(SendedJson):
    TokenEncrypted = SendedJson["token"]
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
    AesKey = private_key.decrypt(AesKeyRsaOnly, padding.PKCS1v15())
    AesKeyIV = private_key.decrypt(AesKeyIVRsaOnly, padding.PKCS1v15())
    cipher = Cipher(algorithms.AES(AesKey), modes.CBC(AesKeyIV), backend=default_backend())

    TokenDecrypted = decryptAES(TokenEncrypted, cipher)

    try:
        user = models.User.objects.get(token=TokenDecrypted)
    except models.User.DoesNotExist:
        return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    taskUUIDEncrypted = SendedJson["taskUUID"]
    taskUUID = decryptAES(taskUUIDEncrypted, cipher)
    try:
        task = models.Task.objects.get(uuid = taskUUID)
    except models.Task.DoesNotExist:
        return JsonResponse({'status': 204, 'errormessage': f"Task Don't exists!"})
    print(task.delete())


    return JsonResponse({'status': 200})
def addTask(SendedJson):
    TokenEncrypted = SendedJson["token"]
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
    AesKey = private_key.decrypt(AesKeyRsaOnly, padding.PKCS1v15())
    AesKeyIV = private_key.decrypt(AesKeyIVRsaOnly, padding.PKCS1v15())
    cipher = Cipher(algorithms.AES(AesKey), modes.CBC(AesKeyIV), backend=default_backend())

    TokenDecrypted = decryptAES(TokenEncrypted, cipher)

    try:
        user = models.User.objects.get(token=TokenDecrypted)
    except models.User.DoesNotExist:
        return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    nameEncrypted = SendedJson["Name"]
    nameTask = decryptAES(nameEncrypted, cipher)
    uuidTask = str(uuid.uuid4())
    task = models.Task()
    task.uuid = uuidTask
    task.name = nameTask
    task.specifiedUser = user
    task.save()

    encryptor = cipher.encryptor()
    block_size = 16  # AES block size is 16 bytes
    padding_length = block_size - len(uuidTask) % block_size
    plaintext_padded = uuidTask + chr(padding_length) * padding_length

    useruuidEncrypted = encryptor.update(plaintext_padded.encode('utf-8')) + encryptor.finalize()
    useruuid = base64.b64encode(useruuidEncrypted).decode()
    return JsonResponse({'status': 200, 'uuid': useruuid})
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