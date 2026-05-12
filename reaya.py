from fastapi import FastAPI, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Literal
import firebase_admin
from firebase_admin import credentials, db
import datetime
import requests
import math
import bcrypt
from PyPDF2 import PdfReader
import io
import os
import json

app = FastAPI()

# ربط Firebase
firebase_key = json.loads(os.getenv("FIREBASE_KEY"))

cred = credentials.Certificate(firebase_key)

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://reayanew-default-rtdb.firebaseio.com/'
    })
# استخراج النص من الملف
def extract_text_from_pdf(file_bytes):
    try:
        reader = PdfReader(file_bytes)
        text = ""

        for page in reader.pages:
            text += page.extract_text() or ""

        return text.strip()

    except:
        return None
# -----------------------
# Models
# -----------------------
#المستخدم وبياناته
class User(BaseModel):
    name: str
    age: int = Field(..., gt=0, lt=120)
    height: float = Field(..., gt=0, lt=250)
    weight: float = Field(..., gt=0, lt=300)
    gender: str
    health_conditions: list[str]
    role: Literal["elderly", "volunteer", "family"]
    phone: str
    password: str = Field(..., min_length=6)
    photo: str

class UpdateUser(BaseModel):
    name: str
    age: int
    height: float
    weight: float
    gender: str
    health_conditions: list[str]
    phone: str
    photo: str

#تسجيل الدخول
class LoginModel(BaseModel):

    phone: str
    password: str

# نسيان كلمة المرور
class ForgotPassword(BaseModel):
    phone: str
    new_password: str = Field(..., min_length=6)

## التذكيرات
class Reminder(BaseModel):
    user_id: str
    title: str
    dose: str
    date: str
    start_time: str
    end_time: str
    repeat_type: Literal["daily", "weekly", "monthly", "none"]
    type: Literal["medicine", "sport", "other", "water"]

#طلب المساعدة
class HelpRequest(BaseModel):

    user_id: str # صاحب الطلب
    title: str  # نوع المساعدة
    description: str # تفاصيل الطلب
    latitude: float # خط العرض
    longitude: float # خط الطول

#الموقع
class Location(BaseModel):
    user_id: str
    latitude: float
    longitude: float

# للخصوصية وتحديد مين يشوف موقع كبير السن
class LocationPrivacy(BaseModel):
    user_id: str
    allow_volunteers: bool
    allow_family: bool

# قبول الطلب
class AcceptRequest(BaseModel):
    volunteer_id: str

# ربط العائلة
class FamilyLink(BaseModel):
    elderly_id: str
    family_member_id: str

#الاشعارات
class Notification(BaseModel):
    user_id: str
    message: str

#رفع التقارير
class HealthReport(BaseModel):
    user_id: str
    report_type: str
    description: str
    file_url: str

#منطقة الأمان
class SafeZone(BaseModel):
    user_id: str
    home_latitude: float
    home_longitude: float

#التواصل مع الموديل
class AIRequest(BaseModel):
    user_id: str

# ميزة اضافية لتحسين تجربة كبير السن وهي التقييم
class Rating(BaseModel):
    volunteer_id: str
    elderly_id: str
    request_id: str
    rating: int
    comment: str

class ChatRequest(BaseModel):
    user_id: str
    message: str

class FamilyReportRequest(BaseModel):
    family_member_id: str
    
#Utility Functions
# دالة حساب المسافات
def calculate_distance(lat1, lon1, lat2, lon2):

    R = 6371  # نصف قطر الأرض بالكيلومتر

    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)

    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) *
         math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    distance = R * c

    return distance

#Authentication APIs
# إضافة مستخدم
# Register user
# -----------------------
######Authentication
@app.post("/register")
def register_user(user: User):
    ref = db.reference("users")
    users = ref.get() or {}
    # عشان نمنع تكرار رقم الهاتف
    for uid, data in users.items():
        if isinstance(data, dict) and data.get("phone") == user.phone:
            return {"message": "Phone already registered"}
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())# تحسين مقترح من الذكاء الاصطناعي
    new_user = ref.push({
        "name": user.name,
        "age": user.age,
        "height": user.height,
        "weight": user.weight,
        "gender": user.gender,
        "health_conditions": user.health_conditions,
        "role": user.role,
        "phone": user.phone,
        "password": hashed_password.decode(),
        "photo": user.photo
    })

    return {
        "message": "User registered successfully",
        "user_id": new_user.key
    }

#تسجيل دخول
@app.post("/login")
def login_user(data: LoginModel):

    ref = db.reference("users")
    users = ref.get() or {}

    for uid, user in users.items():

        if isinstance(user, dict) and user.get("phone") == data.phone:

            stored_password = user.get("password").encode()

            if bcrypt.checkpw(data.password.encode(), stored_password):

                return {
                    "message": "Login success",
                    "user_id": uid,
                    "user_data": user
                }

    return {"message": "Invalid phone or password"}

# نسيان كلمة المرور
@app.post("/forgot-password")
def forgot_password(data: ForgotPassword):

    ref = db.reference("users")
    users = ref.get() or {}

    for uid, user in users.items():

        if isinstance(user, dict) and user.get("phone") == data.phone:

            hashed_password = bcrypt.hashpw(
                data.new_password.encode('utf-8'),
                bcrypt.gensalt()
            )

            ref.child(uid).update({
                "password": hashed_password.decode()
            })

            return {"message": "Password updated successfully"}

    return {"message": "Phone number not found"}

#تسجيل الخروج
@app.post("/logout")
def logout():
    return {
        "message": "User logged out successfully"}
# حذف حساب
@app.delete("/delete-account/{user_id}")
def delete_account(user_id: str):
        # حذف المستخدم
        db.reference("users").child(user_id).delete()
        # حذف الموقع
        db.reference("locations").child(user_id).delete()
        # حذف المنطقة الآمنة
        db.reference("safe_zones").child(user_id).delete()
        # حذف التذكيرات
        reminders = db.reference("reminders").get() or {}
        for rid, data in reminders.items():
            if data.get("user_id") == user_id:
                db.reference("reminders").child(rid).delete()
        # حذف طلبات المساعدة
        requests = db.reference("help_requests").get() or {}
        for rid, data in requests.items():
            if data.get("user_id") == user_id:
                db.reference("help_requests").child(rid).delete()
        # حذف روابط العائلة
        family_links = db.reference("family_links").get() or {}
        for fid, data in family_links.items():
            if data.get("elderly_id") == user_id or data.get("family_member_id") == user_id:
                db.reference("family_links").child(fid).delete()

        # حذف الإشعارات
        notifications = db.reference("notifications").get() or {}
        for nid, data in notifications.items():
            if data.get("user_id") == user_id:
                db.reference("notifications").child(nid).delete()

        # حذف التقارير الصحية
        reports = db.reference("health_reports").get() or {}

        for rid, data in reports.items():
            if data.get("user_id") == user_id:
                db.reference("health_reports").child(rid).delete()

        return {
            "message": "Account and all related data deleted successfully"
        }

###################################################
#Profile APIs
# احضار الملف الشخصي
@app.get("/profile/{user_id}")
def get_profile(user_id: str):

    ref = db.reference("users").child(user_id)
    user = ref.get()
    if not user:
        return {"message": "User not found"}

    return user

# تعديل الملف الشخصي
@app.put("/profile/{user_id}")
def update_profile(user_id: str, user: User):

    ref = db.reference("users").child(user_id)

    ref.update({
        "name": user.name,
        "age": user.age,
        "height": user.height,
        "weight": user.weight,
        "gender": user.gender,
        "health_conditions": user.health_conditions,
        "phone": user.phone,
        "photo": user.photo
    })
    return {
        "message": "Profile updated successfully"
    }

#Reminder APIs
# إضافة تذكير
# -----------------------
@app.post("/reminders")
def add_reminder(reminder: Reminder):

    ref = db.reference("reminders")

    new_reminder = ref.push({
        "user_id": reminder.user_id,
        "title": reminder.title,
        "dose": reminder.dose,
        "date": reminder.date,
        "start_time": reminder.start_time,
        "end_time": reminder.end_time,
        "repeat_type": reminder.repeat_type,
        "type": reminder.type,
        "status": "pending"
    })

    return {
        "message": "Reminder added",
        "reminder_id": new_reminder.key
    }

# عرض التذكيرات
@app.get("/reminders/{user_id}")
def get_reminders(user_id: str):

    ref = db.reference("reminders")
    reminders = ref.get() or {}

    user_reminders = {}

    for rid, data in reminders.items():
        if isinstance(data, dict) and data.get("user_id") == user_id:
            user_reminders[rid] = data

    return user_reminders

# تأكيد أخذ الدواء
@app.post("/reminders/{reminder_id}/complete")
def complete_reminder(reminder_id: str):

    ref = db.reference("reminders").child(reminder_id)

    ref.update({
        "status": "completed",
        "completed_at": datetime.datetime.now().isoformat()
    })

    return {"message": "Reminder completed"}


#تعديل التذكير
@app.put("/reminders/{reminder_id}")
def update_reminder(reminder_id: str, reminder: Reminder):

    ref = db.reference("reminders").child(reminder_id)

    ref.update({
        "title": reminder.title,
        "dose": reminder.dose,
        "date": reminder.date,
        "start_time": reminder.start_time,
        "end_time": reminder.end_time,
        "type": reminder.type,
        "repeat_type": reminder.repeat_type
    })

    return {"message": "Reminder updated"}

#حذف التذكير
@app.delete("/reminders/{reminder_id}")
def delete_reminder(reminder_id: str):

    ref = db.reference("reminders").child(reminder_id)
    ref.delete()

    return {"message": "Reminder deleted"}

# حساب التذكيرات
@app.get("/reminder-stats/{user_id}")
def reminder_stats(user_id: str):

    reminders = db.reference("reminders").get() or {}

    stats = {
        "sport": {"total": 0, "completed": 0},
        "medicine": {"total": 0, "completed": 0},
        "other": {"total": 0, "completed": 0},
        "water": {"total": 0, "completed": 0}
    }

    for r in reminders.values():

        if r.get("user_id") != user_id:
            continue

        r_type = r.get("type", "other")

        if r_type not in stats:
            continue

        # زيادة العدد الكلي
        stats[r_type]["total"] += 1

        # زيادة عدد المؤكد
        if r.get("status") == "completed":
            stats[r_type]["completed"] += 1

    return stats

#تذكير الماء التلقائي
@app.post("/auto-water-reminders/{user_id}")
def create_water_reminders(user_id: str):

    ref = db.reference("reminders")

    # أوقات مقترحة (تقدري تعدليها)
    times = [
        ("08:00", "08:10"),
        ("11:00", "11:10"),
        ("14:00", "14:10"),
        ("17:00", "17:10"),
        ("20:00", "20:10")
    ]

    created_ids = []

    for start, end in times:
        new_reminder = ref.push({
            "user_id": user_id,
            "title": "شرب الماء",
            "dose": "كوب ماء",
            "date": datetime.date.today().isoformat(),
            "repeat_type": "daily",
            "start_time": start,
            "end_time": end,
            "type": "water",   # أو ممكن تسوي نوع جديد "water"
            "status": "pending"
        })
        created_ids.append(new_reminder.key)

    return {
        "message": "5 water reminders created",
        "reminder_ids": created_ids
    }

#Help Request APIs
#طلب مساعدة
@app.post("/help-request")
def create_help_request(request: HelpRequest):
    ref = db.reference("help_requests")
    new_request = ref.push({
        "user_id": request.user_id,
        "title": request.title,
        "description": request.description,
        "latitude": request.latitude,
        "longitude": request.longitude,
        "status": "pending",
        "volunteer_id": None,
        "created_at": datetime.datetime.now().isoformat()
    })
    request_id = new_request.key
    # البحث عن المتطوعين القريبين
    users_ref = db.reference("users")
    users = users_ref.get() or {}
    locations_ref = db.reference("locations")
    locations = locations_ref.get() or {}
    notifications_ref = db.reference("notifications")
    for uid, user in users.items():

        if user.get("role") != "volunteer":
            continue

        volunteer_location = locations.get(uid)
        if not volunteer_location:
            continue

        v_lat = volunteer_location.get("latitude")
        v_lon = volunteer_location.get("longitude")
        distance = calculate_distance(
            request.latitude,
            request.longitude,
            v_lat,
            v_lon
        )
        # إذا كان المتطوع قريب (أقل من 5 كم)
        if distance <= 5:
            notifications_ref.push({
                "user_id": uid,
                "message": "New help request near you",
                "request_id": request_id,
                "distance_km": round(distance, 2),
                "created_at": datetime.datetime.now().isoformat()
            })

    return {
        "message": "Help request created and nearby volunteers notified",
        "request_id": request_id
    }



# -----------------------
# عرض طلبات المساعدة
@app.get("/help-requests")
def get_help_requests():

    ref = db.reference("help_requests")
    data = ref.get() or {}

    return data

# قبول الطلب
@app.post("/help-requests/{request_id}/accept")
def accept_request(request_id: str, data: AcceptRequest):
    requests_ref = db.reference("help_requests")
    requests = requests_ref.get() or {}

    # التحقق إذا كان المتطوع لديه طلب نشط
    for rid, req in requests.items():

        if (req.get("volunteer_id") == data.volunteer_id and
            req.get("status") == "accepted"):

            return {
                "message": "Volunteer already handling another request"
            }
    # التحقق أن الطلب مازال pending
    request_ref = requests_ref.child(request_id)
    request_data = request_ref.get()

    if not request_data:
        return {"message": "Request not found"}

    if request_data.get("status") != "pending":
        return {"message": "Request already taken"}

    # قبول الطلب
    request_ref.update({
        "status": "accepted",
        "volunteer_id": data.volunteer_id
    })
    notifications_ref = db.reference("notifications")
    notifications_ref.push({
        "user_id": request_data.get("user_id"),
        "message": "A volunteer has accepted your help request",
        "created_at": datetime.datetime.now().isoformat()
    })
    #  جلب بيانات كبير السن عشان نعرض رقم التواصل
    elderly_id = request_data.get("user_id")
    elderly = db.reference("users").child(elderly_id).get()
    return {
        "message": "Request accepted successfully",
        "elderly_name": elderly.get("name"),
        "elderly_phone": elderly.get("phone"),
        "elderly_id": elderly_id
    }
# انهاء الطلب
@app.post("/help-requests/{request_id}/complete")
def complete_request(request_id: str):
    ref = db.reference("help_requests").child(request_id)
    ref.update({
        "status": "completed"
    })
    return {
        "message": "Request completed"
    }

# عرض طلبات المستخدم
@app.get("/my-help-requests/{user_id}")
def get_my_requests(user_id: str):

    requests = db.reference("help_requests").get() or {}
    result = []

    for rid, data in requests.items():

        if data.get("user_id") == user_id:

            data["request_id"] = rid
            result.append(data)

    return result
# عرض طلبات المتطوع
# اظهار الطلبات حسب القرب
@app.get("/nearby-help-requests/{volunteer_id}")
def nearby_help_requests(volunteer_id: str):
    # جلب موقع المتطوع
    loc_ref = db.reference("locations").child(volunteer_id)
    volunteer_location = loc_ref.get()
    if not volunteer_location:
        return {"message": "Volunteer location not found"}
    v_lat = volunteer_location.get("latitude")
    v_lon = volunteer_location.get("longitude")
    # جلب جميع الطلبات
    ref = db.reference("help_requests")
    requests = ref.get() or {}
    result = []
    for rid, data in requests.items():
        if data.get("status") != "pending": ## عشان تظهر بس الطلبات اللي ما انتهت
            continue
        r_lat = data.get("latitude")
        r_lon = data.get("longitude")
        distance = calculate_distance(v_lat, v_lon, r_lat, r_lon)
        result.append({
            "request_id": rid,
            "distance_km": round(distance, 2),
            "data": data
        })
    # ترتيب حسب المسافة
    result.sort(key=lambda x: x["distance_km"])
    return result


# عرض بيانات المتطوع لكبير السن
@app.get("/help-request-details/{request_id}")
def get_help_request_details(request_id: str):
    request = db.reference("help_requests").child(request_id).get()
    if not request:
        return {"message": "Request not found"}
    volunteer_id = request.get("volunteer_id")
    if not volunteer_id:
        return {"message": "Volunteer not assigned yet"}
    volunteer = db.reference("users").child(volunteer_id).get()
    elderly_loc = db.reference("locations").child(request.get("user_id")).get()
    volunteer_loc = db.reference("locations").child(volunteer_id).get()
    distance = None
    if elderly_loc and volunteer_loc:
        distance = calculate_distance(
            elderly_loc["latitude"],
            elderly_loc["longitude"],
            volunteer_loc["latitude"],
            volunteer_loc["longitude"]
        )
    return {
        "volunteer_id": volunteer_id,
        "volunteer_name": volunteer.get("name"),
        "volunteer_phone": volunteer.get("phone"),
        "volunteer_photo": volunteer.get("photo"),
        "distance_km": round(distance, 2) if distance else None,
        "volunteer_latitude": volunteer_loc["latitude"],
        "volunteer_longitude": volunteer_loc["longitude"]
    }


# تقييم المتطوع
@app.post("/rate-volunteer")
def rate_volunteer(data: Rating):
    request = db.reference("help_requests").child(data.request_id).get()
    if not request:
        return {"message": "Request not found"}

    if request.get("status") != "completed":
        return {"message": "You can rate only after completing the request"}

    ratings = db.reference("ratings").get() or {}

    for r in ratings.values():
        if r.get("request_id") == data.request_id:
            return {"message": "Request already rated"}

    db.reference("ratings").push({
        "volunteer_id": data.volunteer_id,
        "elderly_id": data.elderly_id,
        "request_id": data.request_id,
        "rating": data.rating,
        "comment": data.comment,
        "created_at": datetime.datetime.now().isoformat()
    })
    return {"message": "Rating submitted"}


# حساب متوسط التقييم
@app.get("/volunteer-stats/{volunteer_id}")
def volunteer_stats(volunteer_id: str):

    ratings = db.reference("ratings").get() or {}
    requests = db.reference("help_requests").get() or {}
    total_rating = 0
    rating_count = 0

    for r in ratings.values():
        if r.get("volunteer_id") == volunteer_id:
            total_rating += r.get("rating", 0)
            rating_count += 1

    completed_requests = 0
    for req in requests.values():
        if req.get("volunteer_id") == volunteer_id and req.get("status") == "completed":
            completed_requests += 1

    avg_rating = 0
    if rating_count > 0:
        avg_rating = round(total_rating / rating_count, 2)

    return {
        "average_rating": avg_rating,
        "completed_services": completed_requests
    }

#Location APIs
#الموقع
@app.post("/update-location")
def update_location(loc: Location):

    ref = db.reference("locations").child(loc.user_id)
    ref.set({
        "latitude": loc.latitude,
        "longitude": loc.longitude
    })

    return {
        "message": "Location updated"
    }
# عرض الموقع
@app.get("/location/{user_id}")
def get_location(user_id: str):

    ref = db.reference("locations").child(user_id)

    location = ref.get()

    if not location:
        return {"message": "Location not found"}

    return location
@app.get("/family/live-location/{family_id}")
def get_live_location_for_family(family_id: str):

    # جلب الرابط
    links = db.reference("family_links").get() or {}

    elderly_id = None

    for link in links.values():

        if link.get("family_member_id") == family_id:

            elderly_id = link.get("elderly_id")
            break

    if not elderly_id:
        return {"message": "No elderly linked"}

    # جلب الموقع الحالي
    location = db.reference("locations").child(elderly_id).get()

    if not location:
        return {"message": "Location not found"}

    return {
        "elderly_id": elderly_id,
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude")
    }
#Safe Zone APIs
# حفظ موقع المنزل
@app.post("/safe-zone")
def set_safe_zone(zone: SafeZone):

    ref = db.reference("safe_zones").child(zone.user_id)

    ref.set({
        "home_latitude": zone.home_latitude,
        "home_longitude": zone.home_longitude,
        "radius_km": 15,
        "status": "inside"
    })

    return {
        "message": "Safe zone saved"
    }

@app.get("/check-safe-zone/{user_id}")
def check_safe_zone(user_id: str):
    zone_ref = db.reference("safe_zones").child(user_id)
    zone = zone_ref.get()
    if not zone:
        return {"message": "Safe zone not set"}

    loc_ref = db.reference("locations").child(user_id)
    location = loc_ref.get()
    if not location:
        return {"message": "User location not found"}
    distance = calculate_distance(
        zone["home_latitude"],
        zone["home_longitude"],
        location["latitude"],
        location["longitude"]
    )
    if distance > zone["radius_km"] and zone.get("status") != "outside":
        zone_ref.update({
            "status": "outside"
        })
        notifications_ref = db.reference("notifications")
        # إشعار للمستخدم نفسه
        notifications_ref.push({
            "user_id": user_id,
            "message": "You have left the safe zone",
            "created_at": datetime.datetime.now().isoformat()
        })
        # جلب أفراد العائلة
        family_links = db.reference("family_links").get() or {}

        for link in family_links.values():

            if link.get("elderly_id") == user_id:

                family_id = link.get("family_member_id")

                notifications_ref.push({
                    "user_id": family_id,
                    "message": "The elderly user has left the safe zone",
                    "created_at": datetime.datetime.now().isoformat()
                })

        return {
            "status": "outside",
            "distance_km": round(distance, 2)
        }

    return {
        "status": "inside",
        "distance_km": round(distance, 2)
    }

#حفظ الاعدادات لخصوصية الموقع
@app.post("/location-privacy")
def set_location_privacy(data: LocationPrivacy):

    ref = db.reference("location_privacy").child(data.user_id)

    ref.set({
        "allow_volunteers": data.allow_volunteers,
        "allow_family": data.allow_family
    })

    return {"message": "Location privacy updated"}

# احضار الاعدادات لخصوصية الموقع
@app.get("/location-privacy/{user_id}")
def get_location_privacy(user_id: str):
    ref = db.reference("location_privacy").child(user_id)
    data = ref.get()

    if not data:
        return {
            "allow_volunteers": False,
            "allow_family": True
        }

    return data

#Family APIs
@app.post("/link-family")
def link_family_by_phone(data: dict):

    elderly_id = data.get("elderly_id")
    family_phone = data.get("phone")

    users = db.reference("users").get() or {}

    family_member_id = None

    # البحث عن فرد العائلة بالرقم
    for uid, user in users.items():

        if not isinstance(user, dict):
            continue

        if (user.get("phone") == family_phone and
            user.get("role") == "family"):

            family_member_id = uid
            break

    # التحقق
    if not family_member_id:
        return {"message": "Family member not found"}

    # منع التكرار
    links_ref = db.reference("family_links")
    links = links_ref.get() or {}

    for link in links.values():

        if (link.get("elderly_id") == elderly_id and
            link.get("family_member_id") == family_member_id):

            return {
                "message": "Already linked"
            }

    # إنشاء الرابط
    new_link = links_ref.push({
        "elderly_id": elderly_id,
        "family_member_id": family_member_id
    })

    # حفظ بيانات كبير السن داخل حساب فرد العائلة
    db.reference("users").child(family_member_id).update({
        "elderly_id": elderly_id
    })

    return {
        "message": "Family member linked successfully",
        "link_id": new_link.key
    }
# عرض العائلة المرتبطة
@app.get("/family/{elderly_id}")
def get_family_members(elderly_id: str):

    links_ref = db.reference("family_links")
    users_ref = db.reference("users")

    links = links_ref.get() or {}
    result = []

    for data in links.values():

        if data.get("elderly_id") == elderly_id:

            family_id = data.get("family_member_id")
            user = users_ref.child(family_id).get()

            if user:
                result.append({
                    "id": family_id,
                    "name": user.get("name", "غير معروف"),
                    "phone": user.get("phone")
                })
            else:
                result.append({
                    "id": family_id,
                    "name": "غير معروف"
                })

    return result
@app.get("/my-elderly/{family_id}")
def get_my_elderly(family_id: str):
    links = db.reference("family_links").get() or {}

    for link in links.values():
        if link.get("family_member_id") == family_id:
            return {
                "elderly_id": link.get("elderly_id")
            }

    return {
        "message": "No elderly linked"
    }
#Notification APIs
#إنشاء إشعار جديد
@app.post("/send-notification")
def send_notification(note: Notification):
    ref = db.reference("notifications")
    new_note = ref.push({
        "user_id": note.user_id,
        "message": note.message,
        "created_at": datetime.datetime.now().isoformat()
    })
    return {
        "message": "Notification sent",
        "notification_id": new_note.key
    }
#جلب إشعارات المستخدم
@app.get("/notifications/{user_id}")
def get_notifications(user_id: str):
    ref = db.reference("notifications")
    notes = ref.get() or {}
    result = []
    for nid, data in notes.items():
        if data.get("user_id") == user_id:

            data["notification_id"] = nid
            result.append(data)
    # ترتيب حسب الأحدث
    result.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return result

#Health Reports
# رفع تقرير صحي
@app.post("/health-report")
async def upload_report(user_id: str, file: UploadFile = File(...)):

    if not file.filename.endswith(".pdf"):
        return {"message": "Only PDF files are allowed"}

    file_bytes = await file.read()

    if not file_bytes:
        return {"message": "Empty file"}

    # استخراج النص
    pdf_text = extract_text_from_pdf(io.BytesIO(file_bytes))

    if not pdf_text or pdf_text.strip() == "":
        return {"message": "PDF contains no readable text"}

    # حفظ النص في Firebase
    ref = db.reference("health_reports")

    new_report = ref.push({
        "user_id": user_id,
        "extracted_text": pdf_text,
        "created_at": datetime.datetime.now().isoformat()
    })

    return {
        "message": "Report uploaded successfully",
        "report_id": new_report.key
    }

# عرض التقرير
@app.get("/health-reports/{user_id}")
def get_reports(user_id: str):
    ref = db.reference("health_reports")
    reports = ref.get() or {}
    result = []
    for rid, data in reports.items():
        if data.get("user_id") == user_id:
            data["report_id"] = rid
            result.append(data)

    return result

#AI Endpoint
@app.post("/chat")
def chat(data: ChatRequest):

    #  جلب بيانات المستخدم
    user = db.reference("users").child(data.user_id).get()

    if not user:
        return {"message": "User not found"}

    #  تجهيز user profile للمودل
    user_profile = {
        "name": user.get("name"),
        "age": user.get("age"),
        "gender": user.get("gender"),
        "health_conditions": user.get("health_conditions"),
        "height": user.get("height"),
        "weight": user.get("weight")
    }

    # =====================================================
    #  جلب آخر المحادثات (Context)
    # =====================================================
    chats_ref = db.reference("ai_chats")
    all_chats = chats_ref.get() or {}

    user_chats = [
        c for c in all_chats.values()
        if c.get("user_id") == data.user_id
    ]

    # ترتيب من الأحدث للأقدم
    user_chats.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    # آخر 5 محادثات
    last_chats = user_chats[:5]

    # تحويلها لنص
    conversation_text = ""

    for chat_item in reversed(last_chats):  # من الأقدم للأحدث
        conversation_text += f"المستخدم: {chat_item.get('message')}\n"
        conversation_text += f"المساعد: {chat_item.get('response', {}).get('reply_text', '')}\n"

    # إضافة الرسالة الجديدة
    conversation_text += f"المستخدم: {data.message}"
    # =========================
    # جلب التقرير الطبي
    # =========================
    reports = db.reference("health_reports").get() or {}

    user_reports = [
        r for r in reports.values()
        if r.get("user_id") == data.user_id
    ]

    report_text = ""

    if user_reports:
        # ترتيب حسب التاريخ
        user_reports.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        report_text = user_reports[0].get("extracted_text", "")[:2000]

    # =====================================================
    #  إرسال للمودل
    # =====================================================
    payload = {
        "text": f"""
هذا تقرير طبي للمستخدم:        
        {report_text}

اعتمد على هذا التقرير في الرد على المستخدم.        

المحادثة:        
        {conversation_text}
        """,
        "user_profile": user_profile
    }

    try:
        response = requests.post(
            "https://riayah-ai-rqhj.onrender.com/generate",
            json=payload,
            timeout=15
        )

        result = response.json()

        # =====================================================
        #  تنفيذ التذكير تلقائي
        # =====================================================
        if result.get("action") == "create_reminder":

            action_data = result.get("action_data", {})

            #  تحديد نوع التذكير
            title = action_data.get("title", "").lower()

            if "دواء" in title:
                reminder_type = "medicine"
            elif "ماء" in title:
                reminder_type = "water"
            elif "رياضة" in title:
                reminder_type = "sport"
            else:
                reminder_type = "other"

            reminder_ref = db.reference("reminders")

            new_reminder = reminder_ref.push({
                "user_id": data.user_id,
                "title": action_data.get("title", "تذكير"),
                "dose": "",
                "date": action_data.get("date", datetime.date.today().isoformat()),
                "start_time": action_data.get("time", "09:00"),
                "end_time": action_data.get("time", "09:10"),
                "repeat_type": "none",
                "type": reminder_type,
                "status": "pending"
            })

            result["created_reminder_id"] = new_reminder.key

        # =====================================================
        #  حفظ المحادثة
        # =====================================================
        db.reference("ai_chats").push({
            "user_id": data.user_id,
            "message": data.message,
            "response": result,
            "created_at": datetime.datetime.now().isoformat()
        })

        return result

    except Exception as e:
        return {
            "message": "AI service unavailable",
            "error": str(e)
        }


@app.post("/generate-report")
def generate_report(data: AIRequest):
    user = db.reference("users").child(data.user_id).get()#بيانات المستخدم
#تجيب كل البيانات من Firebase
    reminders = db.reference("reminders").get() or {}
    help_requests = db.reference("help_requests").get() or {}

    user_reminders = []
    reminder_stats = {
        "sport": {"total": 0, "completed": 0},
        "medicine": {"total": 0, "completed": 0},
        "other": {"total": 0, "completed": 0},
        "water": {"total": 0, "completed": 0}
    }

    # =========================
    # معالجة التذكيرات
    # =========================
    for r in reminders.values():#بس تذكيرات هذا المستخدم

        if r.get("user_id") != data.user_id:
            continue

        # تجهيز بيانات نظيفة للمودل
        user_reminders.append({
            "title": r.get("title"),
            "date": r.get("date"),
            "start_time": r.get("start_time"),
            "end_time": r.get("end_time"),
            "type": r.get("type"),
            "status": r.get("status")
        })

        r_type = r.get("type", "other")

        if r_type not in reminder_stats:
            reminder_stats[r_type] = {"total": 0, "completed": 0}

        reminder_stats[r_type]["total"] += 1

        if r.get("status") == "completed":
            reminder_stats[r_type]["completed"] += 1

    # =========================
    # حساب التزام الأسبوع
    # =========================
    today = datetime.date.today()
    one_week_ago = today - datetime.timedelta(days=7)

    weekly_total = 0
    weekly_completed = 0

    for r in reminders.values():

        if r.get("user_id") != data.user_id:
            continue

        reminder_date = r.get("date")
        if not reminder_date:
            continue

        try:
            r_date = datetime.date.fromisoformat(reminder_date)
        except:
            continue

        if one_week_ago <= r_date <= today:
            weekly_total += 1

            if r.get("status") == "completed":
                weekly_completed += 1

    weekly_adherence = 0
    if weekly_total > 0:
        weekly_adherence = round((weekly_completed / weekly_total) * 100, 2)

    # =========================
    # معالجة طلبات المساعدة
    # =========================
    user_requests = []
    help_stats = {
        "total_requests": 0,
        "completed_requests": 0,
        "pending_requests": 0
    }

    for req in help_requests.values():

        if req.get("user_id") != data.user_id:
            continue

        user_requests.append(req)

        help_stats["total_requests"] += 1

        if req.get("status") == "completed":
            help_stats["completed_requests"] += 1
        elif req.get("status") == "pending":
            help_stats["pending_requests"] += 1

    # =========================
    # البيانات المرسلة للـ AI
    # =========================
    payload = {
        "text": "حلل التزام المستخدم بالتذكيرات خلال الأسبوع وقدم نصائح لتحسين الالتزام",
        "user_profile": {
            "name": user.get("name"),
            "age": user.get("age"),
            "gender": user.get("gender"),
            "health_conditions": user.get("health_conditions"),
            "height": user.get("height"),
            "weight": user.get("weight")
        },
        "reminder_stats": reminder_stats,
        "help_stats": help_stats,
        "reminders": user_reminders,
        "help_requests": user_requests,

        #  الجديد
        "weekly_analysis": {
            "total": weekly_total,
            "completed": weekly_completed,
            "adherence_percentage": weekly_adherence
        }
    }

    # =========================
    # إرسال للمودل
    # =========================
    try:
        response = requests.post(
            "https://riayah-ai-rqhj.onrender.com/generate-report",
            json=payload,
            timeout=15
        )

        result = response.json()

        # حفظ النتيجة
        db.reference("ai_results").push({
            "user_id": data.user_id,
            "result": result,
            "created_at": datetime.datetime.now().isoformat()
        })

        return result

    except Exception as e:
        return {
            "message": "AI service unavailable",
            "error": str(e),
            "sent_data": payload
        }

    # =========================
    # Voice Chat Endpoint
    # =========================

AI_VOICE_URL = "https://riayah-ai-rqhj.onrender.com/voice-chat-full"

@app.post("/voice-chat")
async def voice_chat(file: UploadFile = File(...)):

    audio_bytes = await file.read()

    if not audio_bytes:
        return {"message": "Empty audio file"}

    files = {
        "file": (file.filename, audio_bytes, file.content_type)
    }

    try:
        response = requests.post(
            AI_VOICE_URL,
            files=files,
            timeout=60
        )

        return StreamingResponse(
            io.BytesIO(response.content),
            media_type=response.headers.get("content-type", "audio/wav")
        )

    except Exception as e:
        return {
            "message": "Voice AI failed",
            "error": str(e)
        }
        
@app.post("/family/generate-report")
def generate_family_report(data: FamilyReportRequest):

    # جلب بيانات فرد العائلة
    family_user = db.reference("users").child(
        data.family_member_id
    ).get()

    if not family_user:
        return {"message": "Family member not found"}

    elderly_id = family_user.get("elderly_id")

    if not elderly_id:
        return {"message": "No elderly linked"}

    # توليد التقرير
    return generate_report(
        AIRequest(user_id=elderly_id)
    )
# ----
# تهيئة قاعدة البيانات
@app.post("/init-database")
def init_database():

    root_ref = db.reference('/')
    root_ref.update({
        "users": {"init": True},
        "reminders": {"init": True},
        "help_requests": {"init": True},
        "locations": {"init": True},
        "notifications": {"init": True},
        "family_links": {"init": True},
        "safe_zones": {"init": True},
        "health_reports": {"init": True},
        "ai_results": {"init": True}
    })
    return {
        "message": "Firebase database initialized successfully!"
    }
