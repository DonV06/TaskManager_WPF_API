
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
from API.models import GroupClass, User


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

def getUserWithCipther(SendedJson):
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
        return (models.User.objects.get(token=TokenDecrypted), cipher, (AesKey, AesKeyIV))
    except models.User.DoesNotExist:
        return (None, cipher, (AesKey, AesKeyIV))

@csrf_exempt
def APIRequest(request):
    if request.method == 'POST':
        print(request.body.decode('utf-8'))
        SendedJson = json.loads(request.body.decode('utf-8'))
        if SendedJson["type"] == "loginNOTOKEN": return loginNOTOKEN(SendedJson)
        if SendedJson["type"] == "loginTOKEN": return loginTOKEN(SendedJson)
        if SendedJson["type"] == "addTask": return addTask(SendedJson)
        if SendedJson["type"] == "GroupAddTask": return GroupaddTask(SendedJson)
        if SendedJson["type"] == "getTask": return getTask(SendedJson) #
        if SendedJson["type"] == "refresh": return getAllTasksUUIDs(SendedJson) #
        if SendedJson["type"] == "delTask": return delTask(SendedJson) #
        if SendedJson["type"] == "updateData": return updateData(SendedJson)
        if SendedJson["type"] == "getUpdateDate": return getUpdateDate(SendedJson)
        if SendedJson["type"] == "getAllTasks": return getAllTasks(SendedJson)
        if SendedJson["type"] == "getAllGroupTasks": return getAllGroupTasks(SendedJson)
        if SendedJson["type"] == "updateTask": return updateTask(SendedJson) #
        if SendedJson["type"] == "updateGroups": return updateGroups(SendedJson)
        if SendedJson["type"] == "getGroups": return getGroups(SendedJson)
        if SendedJson["type"] == "userExists": return userExists(SendedJson)
    return JsonResponse({"status": "206"})


def userExists(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    try:
        testing_user = User.objects.get(login=SendedJson["login"])
        return JsonResponse({"status": "200", "user": "True"})
    except models.User.DoesNotExist:
        return JsonResponse({"status": "200", "user": "False"})





def updateGroups(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})

    groupsDataDecrypted = decryptAES(SendedJson["GroupsData"], cipher).split("|*|")[0]
    print(groupsDataDecrypted)
    groupsData = json.loads(groupsDataDecrypted)
    GroupClass.objects.filter(ownerID=userselected).delete()
    for group in groupsData["groups"]:
        newgroup = GroupClass()
        newgroup.uuid = group["uuid"]
        newgroup.name = group["name"]
        newgroup.ownerID = userselected
        newgroup.users = json.dumps({"groups": group["emails"]})
        newgroup.save()
    return JsonResponse({"status": "200"})

def getGroups(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})

    returnData = {"groups": []}
    for group in GroupClass.objects.filter(ownerID=userselected):
        tempJson = {}
        tempJson["emails"] = json.loads(group.users)["groups"]
        tempJson["name"] = group.name
        tempJson["uuid"] = group.uuid
        tempJson["ownerEMAIL"] = group.ownerID.login
        returnData["groups"].append(tempJson)

    for group in GroupClass.objects.filter():
        groups = json.loads(group.users)

        if userselected.login in groups["groups"]:
            tempJson = {}
            tempJson["emails"] = json.loads(group.users)["groups"]
            tempJson["name"] = group.name
            tempJson["uuid"] = group.uuid
            tempJson["ownerEMAIL"] = group.ownerID.login
            returnData["groups"].append(tempJson)

    return JsonResponse({"status": "200", "returndata": json.dumps(returnData)})



def getUpdateDate(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    if (SendedJson["updatedUser"] == "user"):
        prorityList = models.Prority.objects.filter(ownerUUID=userselected.id)
        prorityJson = {'Priorities': []}

        for prority in prorityList:
            prorityJson["Priorities"].append({'name': prority.name, 'level': prority.level, 'uuid': prority.uuid})

        returnTasks = base64.b64encode(json.dumps(prorityJson).encode()).decode()


    else:
        prorityList = models.Prority.objects.filter(ownerUUID=SendedJson["updatedUser"])
        prorityJson = {'Priorities': []}

        for prority in prorityList:
            prorityJson["Priorities"].append({'name': prority.name, 'level': prority.level, 'uuid': prority.uuid})

        returnTasks = base64.b64encode(json.dumps(prorityJson).encode()).decode()
    return JsonResponse({'status': 200, 'returnData': returnTasks})

def updateData(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})

    JsonClear = decryptAES(SendedJson["ProrityJson"], cipher).split("*J*")[0]
    JsonLoaded = json.loads(JsonClear)
    print(SendedJson)
    if SendedJson["userUpdated"] == "user":
        models.Prority.objects.filter(ownerUUID=userselected.id).delete()
        for prority in JsonLoaded["Priorities"]:
            new = models.Prority()
            new.name = prority["name"]
            new.level = int(prority["level"])
            new.uuid = prority["uuid"]
            new.ownerUUID = userselected.id
            new.save()
    else:
        models.Prority.objects.filter(ownerUUID=SendedJson["userUpdated"]).delete()
        for prority in JsonLoaded["Priorities"]:
            new = models.Prority()
            new.name = prority["name"]
            new.level = int(prority["level"])
            new.uuid = prority["uuid"]
            new.ownerUUID = SendedJson["userUpdated"]
            new.save()
    return JsonResponse({'status': 200})


def loginTOKEN(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    userselected.AESkey = str(base64.b64encode(AesKeyCombo[0]).decode())
    userselected.AESkeyIV = str(base64.b64encode(AesKeyCombo[1]).decode())
    userselected.save()
    return JsonResponse({'status': 200})

def updateTask(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    if SendedJson["updatedUser"] == "user": task = models.Task.objects.get(uuid=SendedJson["taskUUID"])
    else: task = models.GroupTask.objects.get(uuid=SendedJson["taskUUID"])

    nameEncrypted = SendedJson["Name"]
    nameTask = decryptAES(nameEncrypted, cipher)
    DateTimeEncrypted = SendedJson["dateTime"]
    dateTimeRaw = decryptAES(DateTimeEncrypted, cipher)

    task.name = nameTask
    task.endTime = dateTimeRaw
    task.specifiedProrityUUID = SendedJson["prorityUUID"]
    task.save()


    return JsonResponse({"status": 200})

def getAllTasks(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    tasks = models.Task.objects.filter(specifiedUser=userselected)
    returnTasks = {"tasks": []}
    for task in tasks:
        returntask = {"name": task.name, "uuid": task.uuid, "dateTime": task.endTime, "priorityUUID": task.specifiedProrityUUID}
        returnTasks["tasks"].append(returntask)

    returnTasks = base64.b64encode(json.dumps(returnTasks).encode()).decode()

    return JsonResponse({"status": 200, 'returnmessage': returnTasks})

def getAllGroupTasks(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    tasks = models.GroupTask.objects.filter(specifiedGroup=models.GroupClass.objects.get(uuid=SendedJson["groupUUID"]))
    returnTasks = {"tasks": []}
    for task in tasks:
        returntask = {"name": task.name, "uuid": task.uuid, "dateTime": task.endTime,
                      "priorityUUID": task.specifiedProrityUUID}
        returnTasks["tasks"].append(returntask)

    returnTasks = base64.b64encode(json.dumps(returnTasks).encode()).decode()

    return JsonResponse({"status": 200, 'returnmessage': returnTasks})

def getAllTasksUUIDs(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    tasks = models.Task.objects.filter(specifiedUser=userselected)
    returnstring = ""
    for _task in tasks:
        returnstring += (_task.uuid + "|")
    return JsonResponse({'status': 200, 'uuids': returnstring})




def getTask(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})

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
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    taskUUIDEncrypted = SendedJson["taskUUID"]
    taskUUID = decryptAES(taskUUIDEncrypted, cipher)
    try:
        if SendedJson["userUpdated"] == "user": task = models.Task.objects.get(uuid = taskUUID)
        else: task = models.GroupTask.objects.get(uuid = taskUUID)
    except models.Task.DoesNotExist:
        return JsonResponse({'status': 204, 'errormessage': f"Task Don't exists!"})

    task.delete()

    return JsonResponse({'status': 200})
def addTask(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    nameEncrypted = SendedJson["Name"]
    nameTask = decryptAES(nameEncrypted, cipher)
    DateTimeEncrypted = SendedJson["dateTime"]
    dateTimeRaw = decryptAES(DateTimeEncrypted, cipher)

    uuidTask = str(uuid.uuid4())

    task = models.Task()
    task.uuid = uuidTask
    task.name = nameTask
    task.endTime = dateTimeRaw
    task.specifiedProrityUUID = SendedJson["prorityUUID"]
    task.specifiedUser = userselected
    task.save()

    encryptor = cipher.encryptor()
    block_size = 16  # AES block size is 16 bytes
    padding_length = block_size - len(uuidTask) % block_size
    plaintext_padded = uuidTask + chr(padding_length) * padding_length

    useruuidEncrypted = encryptor.update(plaintext_padded.encode('utf-8')) + encryptor.finalize()
    useruuid = base64.b64encode(useruuidEncrypted).decode()
    return JsonResponse({'status': 200, 'uuid': useruuid})

def GroupaddTask(SendedJson):
    userselected, cipher, AesKeyCombo = getUserWithCipther(SendedJson)
    if (userselected == None): return JsonResponse({'status': 203, 'errormessage': f"Session don't exists!"})
    nameEncrypted = SendedJson["Name"]
    nameTask = decryptAES(nameEncrypted, cipher)
    DateTimeEncrypted = SendedJson["dateTime"]
    dateTimeRaw = decryptAES(DateTimeEncrypted, cipher)

    GroupUUID = SendedJson["groupUUID"]


    uuidTask = str(uuid.uuid4())

    task = models.GroupTask()
    task.uuid = uuidTask
    task.name = nameTask
    task.endTime = dateTimeRaw
    task.specifiedProrityUUID = SendedJson["prorityUUID"]
    task.specifiedGroup = GroupClass.objects.get(uuid=GroupUUID)
    task.save()

    encryptor = cipher.encryptor()
    block_size = 16  # AES block size is 16 bytes
    padding_length = block_size - len(uuidTask) % block_size
    plaintext_padded = uuidTask + chr(padding_length) * padding_length

    useruuidEncrypted = encryptor.update(plaintext_padded.encode('utf-8')) + encryptor.finalize()
    taskuuid = base64.b64encode(useruuidEncrypted).decode()
    return JsonResponse({'status': 200, 'uuid': taskuuid})

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