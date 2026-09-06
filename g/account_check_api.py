"""Account-check routes; all credentials stay on the server."""
from flask import Blueprint, jsonify, render_template, request

from g.account_check import masked_email
from g.account_check_jobs import ActiveJobError


def create_check_blueprint(jobs):
    bp = Blueprint("account_checks", __name__)

    @bp.get("/account-checks")
    def page():
        return render_template("account_checks.html")

    @bp.before_request
    def limit_body():
        if request.content_length and request.content_length > 10 * 1024 * 1024:
            return jsonify(ok=False, message="请求不能超过 10 MB"), 413

    def body():
        value = request.get_json(silent=True) or {}
        if not isinstance(value, dict):
            raise ValueError("请求体必须是对象")
        return value

    @bp.errorhandler(ValueError)
    def invalid(exc):
        return jsonify(ok=False, message=str(exc)), 400

    @bp.errorhandler(KeyError)
    def missing(_exc):
        return jsonify(ok=False, message="任务不存在"), 404

    @bp.errorhandler(ActiveJobError)
    def active_job(exc):
        return jsonify(ok=False, message=str(exc)), 409

    @bp.get("/api/account-checks")
    def overview():
        return jsonify(ok=True, config=jobs.config(), delay_seconds=jobs.delay_seconds,
                       sources=jobs.files(), jobs=jobs.list_jobs(),
                       recent=[{"id": r.get("id"), "email": masked_email(r.get("email"))} for r in jobs.recent()])

    @bp.post("/api/account-checks/config")
    def config():
        return jsonify(ok=True, config=jobs.save_config(body()))

    @bp.post("/api/account-checks/preview")
    def preview():
        if request.files:
            upload = request.files.get("file")
            if not upload or not upload.filename or not upload.filename.lower().endswith((".txt", ".json")):
                raise ValueError("请选择 TXT 或 JSON 文件")
            raw = upload.read(10 * 1024 * 1024 + 1)
            if len(raw) > 10 * 1024 * 1024:
                raise ValueError("上传文件不能超过 10 MB")
            try:
                text = raw.decode("utf-8-sig")
                result = jobs.preview("upload", text=text, json_format=upload.filename.lower().endswith(".json"))
            except (UnicodeError, ValueError):
                raise ValueError("无法解析上传文件，请检查 UTF-8 编码与 TXT/JSON 格式") from None
        else:
            data = body()
            ids = data.get("ids")
            if ids is not None and not isinstance(ids, list):
                raise ValueError("ids 必须是数组")
            result = jobs.preview(str(data.get("source") or "recent"), names=data.get("files"), ids=ids)
        return jsonify(ok=True, **result)

    @bp.post("/api/account-checks/jobs")
    def start():
        data = body()
        if not isinstance(data.get("passive", False), bool):
            raise ValueError("passive 必须是布尔值")
        return jsonify(ok=True, job=jobs.start(str(data.get("preview_id") or ""), passive=data.get("passive", False))), 202

    @bp.get("/api/account-checks/jobs")
    def listing():
        return jsonify(ok=True, jobs=jobs.list_jobs())

    @bp.delete("/api/account-checks/jobs")
    def clear_history():
        return jsonify(ok=True, deleted=jobs.clear_history())

    @bp.get("/api/account-checks/jobs/<job_id>")
    def detail(job_id):
        return jsonify(ok=True, job=jobs.get(job_id))

    @bp.delete("/api/account-checks/jobs/<job_id>")
    def delete(job_id):
        return jsonify(ok=True, job=jobs.delete(job_id))

    @bp.post("/api/account-checks/jobs/<job_id>/cancel")
    def cancel(job_id):
        return jsonify(ok=True, job=jobs.cancel(job_id))

    @bp.post("/api/account-checks/jobs/<job_id>/apply")
    def apply(job_id):
        return jsonify(ok=True, **jobs.apply(job_id))

    return bp
