import os
import json
import firebase_admin
from firebase_admin import credentials, messaging

class FcmService:
    """
    Firebase Cloud Messaging 서비스: FCM 푸시 알림을 전송합니다.
    - 환경변수 GOOGLE_APPLICATION_CREDENTIALS로 서비스 계정 JSON 경로를 설정
    - '긴급' 키워드 -> siren.mp3 (CriticalSound), '미팅' 키워드 -> default sound
    """
    def __init__(self):
        # 서비스 계정 키 JSON 경로 가져오기
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if cred_path and os.path.exists(cred_path):
            cred = credentials.Certificate(cred_path)
        else:
            # env var가 없으면 Application Default Credentials 사용
            cred = credentials.ApplicationDefault()

        # Firebase Admin SDK 초기화
        firebase_admin.initialize_app(cred)

    def _serialize_message(self, message: messaging.Message) -> dict:
        """
        messaging.Message 객체를 JSON 직렬화 가능한 딕셔너리로 변환합니다.
        """
        serialized = {
            'notification': {
                'title': message.notification.title if message.notification else None,
                'body': message.notification.body if message.notification else None,
            } if message.notification else None,
            'data': message.data,
            'token': message.token,
        }
        # APNS 설정이 있는 경우 추가 직렬화
        if message.apns:
            aps = message.apns.payload.aps
            sound_repr = None
            if aps.sound is not None:
                # CriticalSound 객체인 경우
                if isinstance(aps.sound, messaging.CriticalSound):
                    sound_repr = {
                        'critical': aps.sound.critical,
                        'name': aps.sound.name,
                        'volume': aps.sound.volume,
                    }
                else:
                    # 문자열(sound name)인 경우
                    sound_repr = aps.sound

            serialized['apns'] = {
                'headers': message.apns.headers,
                'payload': {
                    'aps': {
                        'alert': {
                            'title': aps.alert.title if aps.alert else None,
                            'body': aps.alert.body if aps.alert else None,
                        } if aps.alert else None,
                        'sound': sound_repr,
                        'content-available': aps.content_available,
                    }
                }
            }
        return serialized

    def send_push(self, fcm_token: str, title: str, body: str, data: dict = None) -> str:
        """
        FCM 푸시 알림을 전송합니다.
        '긴급' 키워드 -> siren.mp3 (critical),
        '미팅' 키워드 -> 기본 사운드(default)
        """
        # 키워드 분기 (긴급/미팅)
        if '긴급' in body:
            critical_flag = True
        elif '미팅' in body:
            critical_flag = False
        else:
            print("푸시 스킵: '긴급' 또는 '미팅' 키워드 없음")
            return None

        # 페이로드 데이터 준비
        payload_data = data.copy() if data else {}
        mail_data = {'subject': title, 'body': body}
        payload_data['mailData'] = json.dumps(mail_data, ensure_ascii=False)
        payload_data['isCritical'] = 'true' if critical_flag else 'false'

        # 메시지 기본 설정
        message_kwargs = {
            'notification': messaging.Notification(title=title, body=body),
            'data': payload_data,
            'token': fcm_token,
        }

        # APNSConfig 설정
        if critical_flag:
            sound_obj = messaging.CriticalSound(critical=True, name='siren.mp3', volume=0.2)
        else:
            sound_obj = 'default'

        apns_cfg = messaging.APNSConfig(
            headers={'apns-priority': '10'},
            payload=messaging.APNSPayload(
                aps=messaging.Aps(
                    alert=messaging.ApsAlert(title=title, body=body),
                    sound=sound_obj,
                    content_available=True,
                ),
                custom_data=payload_data
            )
        )
        message_kwargs['apns'] = apns_cfg

        # 메시지 생성 및 전송
        message = messaging.Message(**message_kwargs)

        # 디버그: 직렬화된 페이로드 출력
        try:
            print("Sending FCM message:")
            print(json.dumps(self._serialize_message(message), indent=2, ensure_ascii=False))
        except Exception as e:
            print(f"직렬화 로깅 실패: {e}")

        try:
            response = messaging.send(message)
            print(f"푸시 전송 성공: {response}")
            return response
        except Exception as e:
            print(f"푸시 전송 실패: {e}")
            raise
