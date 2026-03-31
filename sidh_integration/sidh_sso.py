import frappe
import base64
import json
import time
from Crypto.Cipher import AES
from frappe import _
from frappe.utils.oauth import redirect_post_login


def unpad(byte_array):
    last_byte = byte_array[-1]
    return byte_array[0:-last_byte]


def decrypt_token(token, crypto_key, crypto_iv):
    try:
        byte_array = base64.b64decode(token)
        key        = base64.b64decode(crypto_key)
        iv         = base64.b64decode(crypto_iv)
        cipher     = AES.new(key, AES.MODE_CBC, iv)
        decrypted  = unpad(cipher.decrypt(byte_array)).decode("UTF-8")
        return json.loads(decrypted)
    except Exception:
        frappe.log_error(frappe.get_traceback(), "SIDH SSO Decryption Failed")
        frappe.throw("Decryption failed")


def validate_token_expiry(data):
    token_time = data.get("time_stamp")
    if not token_time:
        frappe.throw("Invalid token: missing timestamp")
    if int(time.time() * 1000) - token_time > 30000:
        frappe.throw("Token expired")


def validate_payload(data):
    for field in ["candidate_id", "candidate_name", "course_id"]:
        if not data.get(field):
            frappe.throw(f"Invalid token: missing field '{field}'")

    if not frappe.db.exists("LMS Course", data.get("course_id")):
        frappe.throw(f"Course '{data.get('course_id')}' does not exist")

    email = data.get("candidate_email")
    if email and "@" not in email:
        frappe.throw("Invalid token: malformed email address")


def get_email(data):
    return (
        data.get("candidate_email")
        or f"{data.get('candidate_id')}@sidh.in"
    )

def get_user_record(data: dict):
    email = get_email(data)

    if frappe.db.exists("User", email):
        return frappe.get_doc("User", email)       

    user = frappe.new_doc("User")
    user.update({
        "doctype"      : "User",
        "first_name"   : data.get("candidate_name", "").strip(),
        "last_name"    : data.get("last_name", "").strip(),
        "email"        : email,
        "enabled"      : 1,
        "new_password" : frappe.generate_hash(),   
        "user_type"    : "Website User",
    })
    return user                                 

def update_sidh_user(data: dict):
    user = get_user_record(data)          
    update_user_record = user.is_new()

    if not user.enabled:
        frappe.respond_as_web_page(
            _("Not Allowed"),
            _("User {0} is disabled").format(user.email)
        )
        return False

    if not user.get_social_login_userid("sidh"):   
        update_user_record = True
        user.set_social_login_userid(            
            "sidh",
            userid=str(data.get("candidate_id"))   
        )

    if update_user_record:
        user.flags.ignore_permissions = True
        user.flags.no_welcome_mail    = True      

        if default_role := frappe.db.get_single_value("Portal Settings", "default_role"):
            user.add_roles(default_role)          

        user.save()

    return user.email


def enroll_user_in_course(email, course_id):
    if frappe.db.exists("LMS Enrollment", {"course": course_id, "member": email}):
        return
    try:
        enrollment = frappe.get_doc({
            "doctype"     : "LMS Enrollment",
            "course"      : course_id,
            "member"      : email,
            "member_type" : "Student"
        })
        enrollment.insert(ignore_permissions=True)
        frappe.db.commit()
    except Exception:
        frappe.log_error(frappe.get_traceback(), "SIDH SSO Enrollment Failed")
        frappe.throw("Enrollment failed")


@frappe.whitelist(allow_guest=True)
def handle_sidh_sso():
    settings   = frappe.get_single("SIDH Settings")
    crypto_key = settings.get_password(fieldname="crypto_key", raise_exception=False)
    crypto_iv  = settings.get_password(fieldname="crypto_iv",  raise_exception=False)

    token = frappe.request.args.get("token")
    if not token:
        frappe.log_error("No token provided in SIDH SSO request", "SIDH SSO - Missing Token")
        frappe.throw("No token provided")

    data = decrypt_token(token, crypto_key, crypto_iv)
    validate_token_expiry(data)
    validate_payload(data)

    if update_sidh_user(data) is False:
        return
    email = get_email(data)                                    

    course_id = data.get("course_id")

    frappe.local.login_manager.login_as(email)
    frappe.db.commit()                             

    enroll_user_in_course(email, course_id)

    redirect_post_login(desk_user=False,redirect_to=f"/lms/courses/{course_id}")