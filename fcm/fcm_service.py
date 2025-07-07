from firebase_admin import messaging
import json

class FcmService:
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
        payload_data = {key: str(value) for key, value in (data.items() if data else {})}  # 모든 값을 문자열로 변환
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
            print(f"푸시 전송 실패: {str(e)}")
            raise

    def _serialize_message(self, message):
        """
        메시지를 직렬화 가능한 딕셔너리로 변환 (디버깅용)
        """
        return {
            'notification': {
                'title': message.notification.title,
                'body': message.notification.body
            } if message.notification else None,
            'data': message.data,
            'token': message.token,
            'apns': {
                'headers': message.apns.headers,
                'payload': {
                    'aps': {
                        'alert': {
                            'title': message.apns.payload.aps.alert.title,
                            'body': message.apns.payload.aps.alert.body
                        },
                        'sound': {
                            'critical': message.apns.payload.aps.sound.critical,
                            'name': message.apns.payload.aps.sound.name,
                            'volume': message.apns.payload.aps.sound.volume
                        } if isinstance(message.apns.payload.aps.sound, messaging.CriticalSound) else message.apns.payload.aps.sound,
                        'content-available': message.apns.payload.aps.content_available
                    },
                    'custom_data': message.apns.payload.custom_data
                }
            } if message.apns else None
        }