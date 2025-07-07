# import requests
# from bs4 import BeautifulSoup
# import logging
# from typing import Optional, Tuple

# def get_outlook_email_details(
#     client_state: str,
#     message_id: str,
#     user_id: str,
#     token_store: dict,
#     processed_message_ids: set,
#     outlook_auth,
#     redis_client=None,
#     retries: int = 3
# ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
#     """
#     Outlook 메일의 제목, 본문, 발신자를 가져옵니다.

#     Args:
#         client_state: 클라이언트 상태 식별자
#         message_id: 메일 메시지 ID
#         user_id: 사용자 ID
#         token_store: client_state와 fcm_token, 토큰 등을 저장한 딕셔너리
#         processed_message_ids: 처리된 메시지 ID 집합
#         redis_client: Redis 클라이언트 (선택적, 영구 저장용)
#         retries: 재시도 횟수

#     Returns:
#         Tuple containing (subject, body, sender, fcm_token) or (None, None, None, None) if failed
#     """
#     # 로깅 설정
#     logger = logging.getLogger(__name__)

#     # client_state로 FCM 토큰 조회
#     fcm_token = next(
#         (k for k, v in token_store.items() if v.get('client_state') == client_state),
#         None
#     )
#     if not fcm_token:
#         logger.error(f"No fcm_token found for client_state: {client_state}")
#         return None, None, None, None

#     for attempt in range(retries):
#         try:
#             # from auth.outlook_auth import get_valid_token, refresh_token  # outlook_auth 모듈 import
#             token = outlook_auth.get_valid_token(fcm_token)
#             if not token:
#                 logger.error(f"No valid token for fcm_token: {fcm_token}")
#                 return None, None, None, None

#             url = f'https://graph.microsoft.com/v1.0/users/{user_id}/messages/{message_id}'
#             headers = {'Authorization': f'Bearer {token}'}
#             logger.info(f"Fetching email details for message_id: {message_id}, user_id: {user_id}, attempt: {attempt + 1}")
#             resp = requests.get(url, headers=headers)
#             resp.raise_for_status()
#             msg = resp.json()

#             subject = msg.get('subject', 'No Subject')
#             sender = msg.get('from', {}).get('emailAddress', {}).get('address', 'Unknown Sender')
#             content = msg.get('body', {}).get('content', '')
#             content_type = msg.get('body', {}).get('contentType', 'text')

#             # 본문 파싱
#             try:
#                 if content_type == 'html':
#                     body = BeautifulSoup(content, 'html.parser').get_text(separator=' ', strip=True)
#                 else:
#                     body = content
#             except Exception as e:
#                 logger.error(f"Failed to parse email body: {e}")
#                 body = content  # 파싱 실패 시 원본 콘텐츠 반환

#             # 중복 메시지 확인
#             if redis_client:
#                 if redis_client.sismember('processed_message_ids', message_id):
#                     logger.info(f"Message already processed: {message_id}")
#                     return None, None, None, None
#                 redis_client.sadd('processed_message_ids', message_id)
#             else:
#                 if message_id in processed_message_ids:
#                     logger.info(f"Message already processed: {message_id}")
#                     return None, None, None, None
#                 processed_message_ids.add(message_id)

#             logger.info(f"Successfully fetched email details: subject={subject}, sender={sender}")
#             return subject, body, sender, fcm_token

#         except requests.HTTPError as e:
#             logger.error(f"Failed to fetch Outlook email details (attempt {attempt + 1}): {e}")
#             if e.response.status_code == 401 and attempt < retries - 1:
#                 try:
#                     outlook_auth.refresh_token(fcm_token)  # 리프레시 토큰 시도
#                 except Exception as refresh_error:
#                     logger.error(f"Failed to refresh token: {refresh_error}")
#                     return None, None, None, None
#                 continue
#             return None, None, None, None
#         except Exception as e:
#             logger.error(f"Unexpected error in get_outlook_email_details: {e}")
#             return None, None, None, None

#     logger.error(f"Failed to fetch email details after {retries} attempts for message_id: {message_id}")
#     return None, None, None, None