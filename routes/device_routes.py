from flask import Blueprint, request, jsonify
from sqlalchemy import text
from infra.db import SessionLocal
import logging, json

logger = logging.getLogger(__name__)
device_bp = Blueprint('device', __name__)

def _safe_json():
    data = request.get_json(silent=True)
    if data is not None:
        return data
    raw = request.get_data(cache=False, as_text=True) or ""
    try:
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return None

@device_bp.route('/alarm_setting/upsert', methods=['POST'])
def upsert_alarm_setting():
    """
    요청(JSON):
    {
      "device_id": "uuid",                   # 필수
      "platform": "ios" | "android",         # 최초 저장 시 필수(이후 생략 가능)
      "fcm_token": "optional",
      "email_address": "optional",
      "normal_on": true|false,               # optional
      "critical_on": true|false,             # optional
      "critical_until_stopped": true|false   # optional
    }
    동작: device_id 기준 UPSERT, 전달 안된 필드는 기존값 유지
    """
    payload = _safe_json()
    if payload is None:
        return jsonify({"error": "invalid_payload"}), 400

    device_id = (payload.get('device_id') or '').strip()
    platform  = (payload.get('platform') or '').strip().lower()
    fcm_token = payload.get('fcm_token')

    if not device_id:
        return jsonify({"error": "missing_device_id"}), 400
    if platform not in ('ios', 'android'):
        # 최초 INSERT 시도가 아니라면 생략 가능 → 빈 문자열로 넣고 NULL 처리
        platform = ''

    # email_address 정규화(빈 문자열은 무시 → None)
    email_address = payload.get('email_address')
    if isinstance(email_address, str):
        email_address = email_address.strip().lower() or None

    # 불리언(미전달 시 None으로 유지해서 COALESCE가 기존값 보존)
    def b(v): return v if isinstance(v, bool) else None
    normal_on = b(payload.get('normal_on'))
    critical_on = b(payload.get('critical_on'))
    critical_until_stopped = b(payload.get('critical_until_stopped'))

    upsert_sql = text("""
        INSERT INTO alarm_settings
            (device_id, platform, fcm_token, email_address,
             normal_on, critical_on, critical_until_stopped, updated_at)
        VALUES
            (:device_id,
            NULLIF(:platform, ''),
            :fcm_token,
            :email_address,
            IFNULL(:normal_on,              DEFAULT(normal_on)),
            IFNULL(:critical_on,
                   CASE WHEN COALESCE(:critical_until_stopped, 0) = 1
                        THEN 1 ELSE DEFAULT(critical_on) END),            
            IFNULL(:critical_until_stopped, DEFAULT(critical_until_stopped)),
            CURRENT_TIMESTAMP)
        ON DUPLICATE KEY UPDATE
            platform               = COALESCE(VALUES(platform), platform),
            fcm_token              = COALESCE(VALUES(fcm_token), fcm_token),
            email_address          = COALESCE(VALUES(email_address), email_address),
            normal_on              = COALESCE(VALUES(normal_on), normal_on),
            critical_on =
              GREATEST(
                COALESCE(VALUES(critical_on), critical_on),
                COALESCE(VALUES(critical_until_stopped), critical_until_stopped)
              ),
            critical_until_stopped = COALESCE(VALUES(critical_until_stopped), critical_until_stopped),
            updated_at             = CURRENT_TIMESTAMP
    """)

    try:
        with SessionLocal() as db:
            db.execute(upsert_sql, {
                "device_id": device_id,
                "platform": platform,                         # '' → NULLIF → NULL
                "fcm_token": fcm_token,
                "email_address": email_address,               # None이면 기존 유지
                "normal_on": normal_on,                       # None이면 기존 유지
                "critical_on": critical_on,
                "critical_until_stopped": critical_until_stopped,
            })
            db.commit()
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        logger.exception("alarm_setting upsert error: %s", e)
        return jsonify({"error": "internal"}), 500


@device_bp.route('/alarm_setting', methods=['GET'])
def get_alarm_setting():
    """
    쿼리: ?device_id=...
    """
    device_id = (request.args.get('device_id') or '').strip()
    if not device_id:
        return jsonify({"error": "missing_device_id"}), 400

    sel = text("""
        SELECT device_id, platform, fcm_token, email_address,
               normal_on, critical_on, critical_until_stopped, updated_at
          FROM alarm_settings
         WHERE device_id = :device_id
         LIMIT 1
    """)

    try:
        with SessionLocal() as db:
            row = db.execute(sel, {"device_id": device_id}).mappings().first()
        if not row:
            return jsonify({"found": False}), 200

        def to_bool(v):  # MySQL tinyint → 파이썬 bool
            return None if v is None else bool(v)

        return jsonify({
            "found": True,
            "device_id": row["device_id"],
            "platform": row["platform"],
            "fcm_token": row["fcm_token"],
            "email_address": row["email_address"],
            "normal_on": to_bool(row["normal_on"]),
            "critical_on": to_bool(row["critical_on"]),
            "critical_until_stopped": to_bool(row["critical_until_stopped"]),
            "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        }), 200
    except Exception as e:
        logger.exception("alarm_setting get error: %s", e)
        return jsonify({"error": "internal"}), 500
