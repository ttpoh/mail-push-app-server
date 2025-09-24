# gmail_routes.py
from flask import Blueprint, request, jsonify, current_app
import base64
import json
import logging
import uuid
from infra.db import SessionLocal
from models.gmail_users import GmailToken
from utils.gmail_util import get_gmail_email_details
from fcm.fcm_service import FcmService
from cachetools import TTLCache

logger = logging.getLogger(__name__)
gmail_bp = Blueprint('gmail', __name__)
fcm_service = FcmService()

# 로컬 프로세스 캐시 (Redis 없을 때 보완용)
history_cache = TTLCache(maxsize=1000, ttl=3600)  # 1시간
message_cache = TTLCache(maxsize=1000, ttl=86400)  # 1일
# per (email_address, fcm_token)마다 보낸 message_id 추적 (로컬)
seen_set_cache: dict[str, TTLCache] = {}  # key: f"{email}:{fcm_token}" -> TTLCache of message_ids

def _history_dedup_key(email_address: str, history_id: str) -> str:
    return f"pubsub:history:{email_address}:{history_id}"

def _message_push_dedup_key(email_address: str, message_id: str, fcm_token: str) -> str:
    return f"pushed:message:{email_address}:{message_id}:{fcm_token}"

def _message_seen_set_key(email_address: str, fcm_token: str) -> str:
    return f"pushed:set:{email_address}:{fcm_token}"

def _get_redis():
    return getattr(current_app, 'extensions', {}).get('redis')

def _get_local_seen_cache(email_address: str, fcm_token: str) -> TTLCache:
    key = f"{email_address}:{fcm_token}"
    if key not in seen_set_cache:
        # message_id들을 하루 동안 유지
        seen_set_cache[key] = TTLCache(maxsize=1000, ttl=86400)
    return seen_set_cache[key]

@gmail_bp.route('/pubsub_endpoint', methods=['POST'])
def pubsub_endpoint():
    trace_id = str(uuid.uuid4())[:8]
    history_key_claimed = False
    try:
        envelope = request.get_json() or {}
        logger.info("[trace=%s] Pub/Sub received: %s", trace_id, envelope)

        msg = envelope.get('message', {})
        data_encoded = msg.get('data', '')
        try:
            decoded_bytes = base64.b64decode(data_encoded)
            data = json.loads(decoded_bytes.decode())
        except Exception:
            logger.error("[trace=%s] Invalid Pub/Sub payload: %s", trace_id, data_encoded, exc_info=True)
            return jsonify({'error': 'invalid_payload', 'trace_id': trace_id}), 400

        email_address = data.get('emailAddress')
        history_id = data.get('historyId')
        if not email_address or not history_id:
            logger.error("[trace=%s] Missing emailAddress or historyId in Pub/Sub payload: %s", trace_id, data)
            return jsonify({'error': 'missing_fields', 'trace_id': trace_id}), 400

        redis_client = _get_redis()
        history_key = _history_dedup_key(email_address, history_id)

        # atomic하게 historyId 처리 선점: 이미 처리 중이면 스킵
        if redis_client:
            claimed = redis_client.set(history_key, "1", nx=True, ex=3600)
            if not claimed:
                logger.info("[trace=%s] Duplicate Pub/Sub historyId %s for %s, skipping (already claimed)", trace_id, history_id, email_address)
                return jsonify({'status': 'duplicate_history_skipped', 'trace_id': trace_id}), 200
            history_key_claimed = True
        elif history_key in history_cache:
            logger.info("[trace=%s] Duplicate Pub/Sub historyId %s for %s, skipping (local cache)", trace_id, history_id, email_address)
            return jsonify({'status': 'duplicate_history_skipped', 'trace_id': trace_id}), 200
        else:
            # 로컬에 선점
            history_cache[history_key] = True
            history_key_claimed = True

        # FCM 토큰 조회
        with SessionLocal() as db:
            tokens = db.query(GmailToken).filter_by(email_address=email_address).all()
            if not tokens:
                logger.error("[trace=%s] No tokens found for %s", trace_id, email_address)
                return jsonify({'error': f'no_tokens_for_{email_address}', 'trace_id': trace_id}), 404

        # 첫 번째 토큰을 기준으로 이메일 세부 정보 가져오기
        first_token = tokens[0].fcm_token
        subject, body, sender, matched, message_id = get_gmail_email_details(
            first_token, history_id, redis_client=redis_client
        )

        if not subject or not matched or not message_id:
            # 새로운 메시지가 없거나 매칭 안 된 경우: historyKey는 이미 선점된 상태 → 그대로 유지
            logger.info("[trace=%s] No new or unmatched email for history_id %s (email=%s)", trace_id, history_id, email_address)
            return jsonify({'status': 'no_new_message_or_unmatched', 'trace_id': trace_id}), 200

        notified = 0
        for token_entry in tokens:
            push_key = _message_push_dedup_key(email_address, message_id, token_entry.fcm_token)
            seen_set_key = _message_seen_set_key(email_address, token_entry.fcm_token)
            already_pushed = False

            # 기존 race-condition 방지용 선점
            if redis_client:
                was_set = redis_client.set(push_key, "1", nx=True, ex=86400)
                if not was_set:
                    already_pushed = True
            elif push_key in message_cache:
                already_pushed = True

            if already_pushed:
                logger.info("[trace=%s] Already pushed message %s to %s, skipping (push_key)", trace_id, message_id, token_entry.fcm_token)
                continue

            # 추가: 같은 message_id가 이미 그 토큰에 대해 보낸 적 있는지 (set 기반)
            already_seen = False
            if redis_client:
                if redis_client.sismember(seen_set_key, message_id):
                    already_seen = True
            else:
                local_seen = _get_local_seen_cache(email_address, token_entry.fcm_token)
                if message_id in local_seen:
                    already_seen = True

            if already_seen:
                logger.info("[trace=%s] message_id %s already delivered previously to %s (seen_set), skipping", trace_id, message_id, token_entry.fcm_token)
                continue

            try:
                fcm_service.send_push_for_email(
                    token_entry.fcm_token,
                    email_address,
                    subject,
                    body,
                    sender,
                    message_id=message_id,
                    extra_data={'historyId': history_id, 'trace_id': trace_id}
                )
                notified += 1

                # 성공 시 dedupe 기록 유지
                if redis_client:
                    redis_client.expire(push_key, 86400)
                    redis_client.sadd(seen_set_key, message_id)
                    redis_client.expire(seen_set_key, 86400)
                else:
                    message_cache[push_key] = True
                    local_seen = _get_local_seen_cache(email_address, token_entry.fcm_token)
                    local_seen[message_id] = True

                logger.info("[trace=%s] Push sent for message %s to %s", trace_id, message_id, token_entry.fcm_token)
            except Exception as e:
                logger.error("[trace=%s] FCM send failure to %s: %s", trace_id, token_entry.fcm_token, e, exc_info=True)
                # 실패한 경우: push_key 롤백, seen_set은 건드리지 않음 (전송이 안 된 것이므로)
                if redis_client:
                    try:
                        redis_client.delete(push_key)
                    except Exception:
                        logger.warning("[trace=%s] Failed to rollback push_key in redis: %s", trace_id, push_key)
                else:
                    message_cache.pop(push_key, None)
                # 계속 다른 토큰으로 시도

        # notified > 0일 때만 historyId 확정; 하나도 notify 안 됐으면 rollback 해서 다음에 재시도 허용
        if notified > 0:
            logger.info("[trace=%s] Finished processing historyId %s for %s, notified %d tokens", trace_id, history_id, email_address, notified)
        else:
            logger.info("[trace=%s] No token was notified for historyId %s (maybe all were deduped or failures)", trace_id, history_id)
            # 이미 선점한 history_key를 롤백해서 재시도 가능하게
            if redis_client:
                try:
                    redis_client.delete(history_key)
                except Exception:
                    logger.warning("[trace=%s] Failed to rollback history_key in redis: %s", trace_id, history_key)
            else:
                history_cache.pop(history_key, None)

        return jsonify({'status': 'gmail_processed', 'tokens_notified': notified, 'trace_id': trace_id}), 200

    except Exception as e:
        logger.exception("[trace=%s] Pub/Sub endpoint error: %s", trace_id, e)
        # 오류 시에도 historyId 롤백 (다음에 Pub/Sub 재전송 받으면 다시 시도)
        if history_key_claimed:
            if redis_client := _get_redis():
                try:
                    redis_client.delete(history_key)
                except Exception:
                    logger.warning("[trace=%s] Failed to rollback history_key after exception: %s", trace_id, history_key)
            else:
                history_cache.pop(history_key, None)
        return jsonify({'error': 'internal', 'trace_id': trace_id}), 500
