# outlook_routes.py
from flask import Blueprint, request, jsonify, current_app
from fcm.fcm_service import FcmService
from auth.outlook_auth import OutlookAuth
from models.outlook_users import OutlookToken
from infra.db import SessionLocal
from utils.outlook_util import get_outlook_email_details
from infra.redis_client import redis_client as global_redis_client
import logging
import json
import uuid
from datetime import datetime
from cachetools import TTLCache

logger = logging.getLogger(__name__)

outlook_bp = Blueprint('outlook', __name__)
fcm_service = FcmService()

# ---- Gmail 로직과 유사한 로컬 보조 캐시( Redis 부재 대비 ) ----
message_cache = TTLCache(maxsize=1000, ttl=86400)  # 1일
seen_set_cache: dict[str, TTLCache] = {}  # key: f"{email}:{fcm_token}" -> TTLCache of message_ids

def _get_redis():
    """
    앱 확장에 올라간 redis 우선, 없으면 전역(global_redis_client) 사용
    """
    ext_redis = getattr(current_app, 'extensions', {}).get('redis')
    return ext_redis or global_redis_client

def _message_push_dedup_key(email_address: str, message_id: str, fcm_token: str) -> str:
    return f"outlook:pushed:message:{email_address}:{message_id}:{fcm_token}"

def _message_seen_set_key(email_address: str, fcm_token: str) -> str:
    return f"outlook:pushed:set:{email_address}:{fcm_token}"

def _get_local_seen_cache(email_address: str, fcm_token: str) -> TTLCache:
    key = f"{email_address}:{fcm_token}"
    if key not in seen_set_cache:
        seen_set_cache[key] = TTLCache(maxsize=1000, ttl=86400)
    return seen_set_cache[key]

@outlook_bp.route('/outlook_webhook', methods=['GET', 'POST'])
def outlook_webhook():
    trace_id = str(uuid.uuid4())[:8]
    logger.info("[trace=%s] Outlook 웹훅 요청: %s, args=%s, headers=%s",
                trace_id, request.method, dict(request.args), dict(request.headers))

    # 구독 검증 (Graph subscriptions)
    if 'validationToken' in request.args:
        token = request.args['validationToken']
        logger.info("[trace=%s] validationToken 응답", trace_id)
        return token, 200, {'Content-Type': 'text/plain'}

    # 페이로드 파싱
    try:
        payload = request.get_json(silent=True) or {}
        logger.info("[trace=%s] Outlook 웹훅 페이로드: %s", trace_id, payload)
    except Exception as e:
        logger.error("[trace=%s] 웹훅 페이로드 파싱 실패: %s", trace_id, e, exc_info=True)
        return jsonify({'status': 'invalid_payload', 'trace_id': trace_id}), 400

    # OutlookAuth 인스턴스 (필요 시)
    outlook_auth = OutlookAuth(
        client_id=request.headers.get('X-Outlook-Client-Id'),
    )

    rds = _get_redis()

    # Graph는 payload["value"] 배열로 알림 전달
    value_list = payload.get('value', [])
    if not isinstance(value_list, list):
        logger.error("[trace=%s] payload.value 형식 오류", trace_id)
        return jsonify({'status': 'invalid_value', 'trace_id': trace_id}), 400

    notified_total = 0

    with SessionLocal() as db:
        for note in value_list:
            client_state = note.get('clientState')
            msg_id = (note.get('resourceData') or {}).get('id')
            logger.info("[trace=%s] [웹훅 아이템] client_state=%s, msg_id=%s",
                        trace_id, client_state, msg_id)

            if not client_state or not msg_id:
                logger.warning("[trace=%s] 페이로드에 client_state 또는 msg_id 누락", trace_id)
                continue

            # client_state -> 메인 토큰(이메일 식별에 필요)
            main_token = db.query(OutlookToken).filter_by(client_state=client_state).first()
            if not main_token:
                logger.warning("[trace=%s] client_state에 대한 토큰 없음: %s", trace_id, client_state)
                continue

            email_address = main_token.email_address
            logger.info("[trace=%s] 이메일 처리 중: %s", trace_id, email_address)

            try:
                # 메일 상세 조회
                # get_outlook_email_details(...) 시그니처는 프로젝트에 맞게 이미 구현됨
                subject, body, sender, _ = get_outlook_email_details(
                    client_state=client_state,
                    message_id=msg_id,
                    user_id=email_address,
                    processed_message_ids=None,   # Redis에만 의존
                    redis_client=rds,
                    outlook_auth=outlook_auth
                )

                if not subject:
                    logger.info("[trace=%s] msg_id=%s 에 대한 이메일 세부 정보 없음", trace_id, msg_id)
                    continue

                # 동일 이메일의 모든 기기 토큰 조회
                tokens = db.query(OutlookToken).filter_by(email_address=email_address).all()
                if not tokens:
                    logger.warning("[trace=%s] 이메일 %s 에 대한 토큰이 없음", trace_id, email_address)
                    continue

                # 각 토큰별 디듑/전송
                for t in tokens:
                    push_key = _message_push_dedup_key(email_address, msg_id, t.fcm_token)
                    seen_set_key = _message_seen_set_key(email_address, t.fcm_token)

                    # 1) push_key 선점 (race condition 방지)
                    already_pushed = False
                    if rds:
                        try:
                            was_set = rds.set(push_key, "1", nx=True, ex=86400)
                            if not was_set:
                                already_pushed = True
                        except Exception:
                            # Redis 오류 시 로컬 캐시로 폴백
                            already_pushed = push_key in message_cache
                    else:
                        already_pushed = push_key in message_cache

                    if already_pushed:
                        logger.info("[trace=%s] 이미 푸시됨(push_key) msg=%s token=%s",
                                    trace_id, msg_id, t.fcm_token)
                        continue

                    # 2) 같은 토큰에 동일 message_id 과거 전송 여부 (seen_set)
                    already_seen = False
                    if rds:
                        try:
                            if rds.sismember(seen_set_key, msg_id):
                                already_seen = True
                        except Exception:
                            # Redis 오류 시 로컬로 폴백
                            local_seen = _get_local_seen_cache(email_address, t.fcm_token)
                            already_seen = msg_id in local_seen
                    else:
                        local_seen = _get_local_seen_cache(email_address, t.fcm_token)
                        already_seen = msg_id in local_seen

                    if already_seen:
                        logger.info("[trace=%s] 이미 seen_set에 기록된 메시지 msg=%s token=%s",
                                    trace_id, msg_id, t.fcm_token)
                        # push_key 롤백(이미 전송된 동일건이므로 재시도 허용X가 자연스럽지만,
                        # seen_set에 있으니 어차피 스킵됨. push_key는 유지해도 무방)
                        continue

                    # 3) 전송 시도
                    try:
                        # FcmService 시그니처: (fcm_token, email_address, subject, body, sender, message_id, extra_data)
                        fcm_service.send_push_for_email(
                            t.fcm_token,
                            email_address,
                            subject,
                            body or "",
                            sender or "",
                            message_id=msg_id,
                            extra_data={'trace_id': trace_id}
                        )
                        notified_total += 1

                        # 성공 시 디듑 키/셋 유지
                        if rds:
                            try:
                                rds.expire(push_key, 86400)
                                rds.sadd(seen_set_key, msg_id)
                                rds.expire(seen_set_key, 86400)
                            except Exception:
                                # Redis 장애 시 로컬로 유지
                                message_cache[push_key] = True
                                local_seen = _get_local_seen_cache(email_address, t.fcm_token)
                                local_seen[msg_id] = True
                        else:
                            message_cache[push_key] = True
                            local_seen = _get_local_seen_cache(email_address, t.fcm_token)
                            local_seen[msg_id] = True

                        logger.info("[trace=%s] Outlook push sent: email=%s msg=%s token=%s",
                                    trace_id, email_address, msg_id, t.fcm_token)

                    except Exception as e:
                        logger.error("[trace=%s] FCM 전송 실패 token=%s msg=%s: %s",
                                     trace_id, t.fcm_token, msg_id, e, exc_info=True)
                        # 실패 시 push_key 롤백, seen_set은 미기록 상태 유지
                        if rds:
                            try:
                                rds.delete(push_key)
                            except Exception:
                                logger.warning("[trace=%s] Redis push_key 롤백 실패: %s", trace_id, push_key)
                        else:
                            message_cache.pop(push_key, None)
                        # 다른 토큰은 계속 시도

            except Exception as e:
                logger.error("[trace=%s] msg_id=%s 처리 실패: %s", trace_id, msg_id, e, exc_info=True)
                # 이 note는 건너뛰고 다음으로

    return jsonify({'status': 'outlook_processed', 'tokens_notified': notified_total, 'trace_id': trace_id}), 200
