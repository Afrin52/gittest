# from pyfcm import FCMNotification

# def send_notification(device_id, title, message):
#     url = {
#         "http": "http://127.0.0.1:8000"
#     }
#     api_key = ""
#     push_service = FCMNotification(api_key=api_key, url=url)
#     registration_ids = device_id
#     message_title = "Uber update"
#     message_body = "Hi john, your customized news for today is ready"
#     result = push_service.notify_single_device(registration_id=registration_id, message_title=message_title, message_body=message_body)
#     print("result============", result)
#     return result

from pyfcm import FCMNotification
def send_notification(device_id, title, message):
    proxy_dict = {
    "http"  : "http://127.0.0.1:8000",
    "https" : "http://127.0.0.1:8000",
    }
    api_key = " AAAAyf5-org:APA91bG4Utl8gTk5yzDC_K6v6WUfJ4PEyOhN9bklqclhCw1gCke1zZjpqWzBBlTuJNurleEIWAyop5WhUfbuwluEAx2MQip0PtShc32qLlWPlBWz3m4NTXyzKn41l817bK66t5f-q_Nu"
    push_service = FCMNotification(api_key=api_key, proxy_dict=proxy_dict)
    device_1 = "AAAA8lRYGGg:APA91bHJXPJbe-5MN1O4Cf3pEDikOpYrgrX4UxvS-DeDcPndaseh9_51fWuaqbkPKgOIrpCboDNpBn6T5jSxU6DwKtLhdzim0C5w9Xqh1nvdfvAr4_2iqNtcsEhZmOOgoNtbEYQpoUph"
    registration_ids = [device_1]
    message_title = "Uber update"
    message_body = "Hope you're having fun this weekend, don't forget to check today's news"
    result = push_service.notify_single_device(registration_id=registration_ids, message_title=message_title, message_body=message_body)
    print("result------>", result)
