from pathlib import Path
from fastapi.responses import StreamingResponse, FileResponse
from fastapi import FastAPI, HTTPException, Depends, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone
from bson import ObjectId
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import os
import jwt
import bcrypt
import csv
import io

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL", "mongodb://127.0.0.1:27017")
DB_NAME = os.getenv("DB_NAME", "sentinel_crime_db")
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "720"))

app = FastAPI(title="SENTINEL Crime System API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

client = None
db = None


def now_utc():
    return datetime.now(timezone.utc)


def clean_doc(doc: Dict[str, Any]):
    if not doc:
        return doc

    doc["_id"] = str(doc["_id"])

    for key in ["createdAt", "updatedAt", "occurredAt"]:
        if isinstance(doc.get(key), datetime):
            doc[key] = doc[key].isoformat()

    if "statusHistory" in doc:
        for item in doc["statusHistory"]:
            if isinstance(item.get("at"), datetime):
                item["at"] = item["at"].isoformat()

    return doc


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def create_token(user: Dict[str, Any]) -> str:
    payload = {
        "sub": str(user["_id"]),
        "email": user["email"],
        "role": user["role"],
        "exp": now_utc() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(request: Request):
    token_from_query = request.query_params.get("token")
    auth = request.headers.get("Authorization")

    token = None

    if auth and auth.startswith("Bearer "):
        token = auth.replace("Bearer ", "").strip()

    if token_from_query:
        token = token_from_query.strip()

    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = payload.get("sub")

    user = await db.users.find_one({"_id": ObjectId(user_id)})

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def require_roles(*roles):
    async def checker(user=Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Permission denied")
        return user

    return checker


class LoginIn(BaseModel):
    email: str
    password: str


class ComplaintIn(BaseModel):
    crime_type: str = Field(..., examples=["theft"])
    severity: str = Field(..., examples=["medium"])
    area: str = Field(..., examples=["Saddar Rawalpindi"])
    description: str
    latitude: float
    longitude: float
    reporter_name: Optional[str] = "Anonymous"
    reporter_phone: Optional[str] = ""


class CrimeIn(BaseModel):
    crime_type: str
    severity: str
    area: str
    description: str
    latitude: float
    longitude: float
    status: Optional[str] = "reported"


class StatusIn(BaseModel):
    status: str


VALID_SEVERITY = {"low", "medium", "high", "critical"}
VALID_STATUS = {"reported", "verified", "investigating", "resolved", "rejected"}


@app.on_event("startup")
async def startup():
    global client, db

    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]

    await db.crime_reports.create_index([("location", "2dsphere")])
    await db.crime_reports.create_index([("crime_type", 1)])
    await db.crime_reports.create_index([("severity", 1)])
    await db.crime_reports.create_index([("status", 1)])
    await db.crime_reports.create_index([("area", 1)])
    await db.crime_reports.create_index([("occurredAt", -1)])
    await db.users.create_index("email", unique=True)

    print(f"MongoDB connected: {MONGO_URL}")
    print(f"Database selected: {DB_NAME}")
    print("Indexes synced: location 2dsphere + filtering indexes")


@app.on_event("shutdown")
async def shutdown():
    if client:
        client.close()


@app.get("/api/health")
async def health():
    total = await db.crime_reports.count_documents({})

    return {
        "success": True,
        "message": "SENTINEL backend is running",
        "database": DB_NAME,
        "totalReports": total
    }


@app.post("/api/auth/login")
async def login(data: LoginIn):
    user = await db.users.find_one({"email": data.email.lower().strip()})

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(user)

    return {
        "success": True,
        "token": token,
        "user": {
            "_id": str(user["_id"]),
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }


@app.post("/api/complaints")
async def file_complaint(data: ComplaintIn):
    severity = data.severity.lower().strip()
    crime_type = data.crime_type.lower().strip()

    if severity not in VALID_SEVERITY:
        raise HTTPException(status_code=400, detail="Invalid severity")

    ref = "SEN-" + now_utc().strftime("%Y%m%d%H%M%S")

    doc = {
        "referenceNo": ref,
        "crime_type": crime_type,
        "severity": severity,
        "area": data.area.strip(),
        "description": data.description.strip(),
        "location": {
            "type": "Point",
            "coordinates": [data.longitude, data.latitude]
        },
        "status": "reported",
        "source": "public_complaint",
        "reporter": {
            "name": data.reporter_name or "Anonymous",
            "phone": data.reporter_phone or ""
        },
        "occurredAt": now_utc(),
        "createdAt": now_utc(),
        "updatedAt": now_utc(),
        "statusHistory": [
            {
                "status": "reported",
                "at": now_utc(),
                "by": "public"
            }
        ]
    }

    result = await db.crime_reports.insert_one(doc)
    crime_id = str(result.inserted_id)

    notif = {
        "title": "New public crime complaint",
        "message": f"{crime_type.upper()} reported in {data.area}",
        "crimeId": crime_id,
        "referenceNo": ref,
        "read": False,
        "createdAt": now_utc()
    }

    await db.notifications.insert_one(notif)

    inserted = await db.crime_reports.find_one({"_id": result.inserted_id})

    return {
        "success": True,
        "message": "Complaint filed successfully. Police notification created.",
        "referenceNo": ref,
        "data": clean_doc(inserted)
    }


@app.post("/api/crimes")
async def create_crime(
    data: CrimeIn,
    user=Depends(require_roles("admin", "police"))
):
    severity = data.severity.lower().strip()
    status = data.status.lower().strip()

    if severity not in VALID_SEVERITY:
        raise HTTPException(status_code=400, detail="Invalid severity")

    if status not in VALID_STATUS:
        raise HTTPException(status_code=400, detail="Invalid status")

    doc = {
        "referenceNo": "POL-" + now_utc().strftime("%Y%m%d%H%M%S"),
        "crime_type": data.crime_type.lower().strip(),
        "severity": severity,
        "area": data.area.strip(),
        "description": data.description.strip(),
        "location": {
            "type": "Point",
            "coordinates": [data.longitude, data.latitude]
        },
        "status": status,
        "source": "police_dashboard",
        "createdBy": str(user["_id"]),
        "occurredAt": now_utc(),
        "createdAt": now_utc(),
        "updatedAt": now_utc(),
        "statusHistory": [
            {
                "status": status,
                "at": now_utc(),
                "by": user["email"]
            }
        ]
    }

    result = await db.crime_reports.insert_one(doc)
    inserted = await db.crime_reports.find_one({"_id": result.inserted_id})

    return {
        "success": True,
        "data": clean_doc(inserted)
    }


@app.get("/api/crimes")
async def list_crimes(
    area: Optional[str] = None,
    crime_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_roles("admin", "police", "analyst"))
):
    query = {}

    if area:
        query["area"] = {"$regex": area, "$options": "i"}

    if crime_type:
        query["crime_type"] = crime_type.lower()

    if severity:
        query["severity"] = severity.lower()

    if status:
        query["status"] = status.lower()

    cursor = db.crime_reports.find(query).sort("createdAt", -1).limit(limit)

    rows = [clean_doc(d) async for d in cursor]
    total = await db.crime_reports.count_documents(query)

    return {
        "success": True,
        "total": total,
        "data": rows
    }


@app.get("/api/crimes/near")
async def crimes_near(
    lat: float,
    lng: float,
    radius: int = Query(1000, ge=50, le=20000),
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_roles("admin", "police", "analyst"))
):
    pipeline = [
        {
            "$geoNear": {
                "near": {
                    "type": "Point",
                    "coordinates": [lng, lat]
                },
                "distanceField": "distanceMeters",
                "maxDistance": radius,
                "spherical": True
            }
        },
        {
            "$sort": {
                "distanceMeters": 1
            }
        },
        {
            "$limit": limit
        }
    ]

    rows = []

    async for doc in db.crime_reports.aggregate(pipeline):
        doc = clean_doc(doc)
        doc["distanceMeters"] = round(doc.get("distanceMeters", 0), 2)
        rows.append(doc)

    return {
        "success": True,
        "count": len(rows),
        "data": rows
    }


@app.patch("/api/crimes/{crime_id}/status")
async def update_status(
    crime_id: str,
    data: StatusIn,
    user=Depends(require_roles("admin", "police"))
):
    if data.status not in VALID_STATUS:
        raise HTTPException(status_code=400, detail="Invalid status")

    result = await db.crime_reports.update_one(
        {
            "_id": ObjectId(crime_id)
        },
        {
            "$set": {
                "status": data.status,
                "updatedAt": now_utc()
            },
            "$push": {
                "statusHistory": {
                    "status": data.status,
                    "at": now_utc(),
                    "by": user["email"]
                }
            }
        }
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Crime not found")

    updated = await db.crime_reports.find_one({"_id": ObjectId(crime_id)})

    return {
        "success": True,
        "data": clean_doc(updated)
    }


@app.delete("/api/crimes/{crime_id}")
async def delete_crime(
    crime_id: str,
    user=Depends(require_roles("admin"))
):
    result = await db.crime_reports.delete_one({"_id": ObjectId(crime_id)})

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Crime not found")

    return {
        "success": True,
        "message": "Crime deleted"
    }


@app.get("/api/notifications")
async def notifications(
    user=Depends(require_roles("admin", "police"))
):
    cursor = db.notifications.find({}).sort("createdAt", -1).limit(50)

    rows = [clean_doc(d) async for d in cursor]
    unread = await db.notifications.count_documents({"read": False})

    return {
        "success": True,
        "unread": unread,
        "data": rows
    }


@app.get("/api/analytics/summary")
async def summary(
    user=Depends(require_roles("admin", "police", "analyst"))
):
    total = await db.crime_reports.count_documents({})
    critical = await db.crime_reports.count_documents({"severity": "critical"})
    resolved = await db.crime_reports.count_documents({"status": "resolved"})

    today_start = now_utc().replace(hour=0, minute=0, second=0, microsecond=0)
    today = await db.crime_reports.count_documents({"createdAt": {"$gte": today_start}})

    return {
        "success": True,
        "data": {
            "total": total,
            "today": today,
            "critical": critical,
            "resolved": resolved
        }
    }


@app.get("/api/analytics/by-type")
async def by_type(
    user=Depends(require_roles("admin", "police", "analyst"))
):
    pipeline = [
        {
            "$group": {
                "_id": "$crime_type",
                "count": {
                    "$sum": 1
                }
            }
        },
        {
            "$sort": {
                "count": -1
            }
        }
    ]

    data = [d async for d in db.crime_reports.aggregate(pipeline)]

    return {
        "success": True,
        "data": data
    }


@app.get("/api/analytics/trends")
async def trends(
    user=Depends(require_roles("admin", "police", "analyst"))
):
    pipeline = [
        {
            "$group": {
                "_id": {
                    "year": {
                        "$year": "$occurredAt"
                    },
                    "month": {
                        "$month": "$occurredAt"
                    }
                },
                "count": {
                    "$sum": 1
                }
            }
        },
        {
            "$sort": {
                "_id.year": 1,
                "_id.month": 1
            }
        }
    ]

    data = [d async for d in db.crime_reports.aggregate(pipeline)]

    return {
        "success": True,
        "data": data
    }


@app.get("/api/hotspots")
async def hotspots(
    days: int = Query(30, ge=1, le=365),
    radius: int = Query(500, ge=100, le=5000),
    threshold: int = Query(3, ge=1, le=100),
    user=Depends(require_roles("admin", "police", "analyst"))
):
    since = now_utc() - timedelta(days=days)

    reports = [
        d async for d in db.crime_reports.find({"occurredAt": {"$gte": since}})
    ]

    results = []
    used_areas = set()

    for report in reports:
        area = report.get("area", "Unknown")

        if area in used_areas:
            continue

        coords = report["location"]["coordinates"]
        lng = coords[0]
        lat = coords[1]

        near_pipeline = [
            {
                "$geoNear": {
                    "near": {
                        "type": "Point",
                        "coordinates": [lng, lat]
                    },
                    "distanceField": "distanceMeters",
                    "maxDistance": radius,
                    "spherical": True,
                    "query": {
                        "occurredAt": {
                            "$gte": since
                        }
                    }
                }
            }
        ]

        nearby = [d async for d in db.crime_reports.aggregate(near_pipeline)]

        if len(nearby) >= threshold:
            used_areas.add(area)

            types = {}
            severity_score = 0

            for n in nearby:
                crime_type = n.get("crime_type", "unknown")
                types[crime_type] = types.get(crime_type, 0) + 1

                sev = n.get("severity")

                if sev == "critical":
                    severity_score += 4
                elif sev == "high":
                    severity_score += 3
                elif sev == "medium":
                    severity_score += 2
                else:
                    severity_score += 1

            if severity_score >= 15:
                risk = "HIGH"
            elif severity_score >= 8:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            results.append({
                "sector": area,
                "count": len(nearby),
                "latitude": lat,
                "longitude": lng,
                "radiusMeters": radius,
                "riskLevel": risk,
                "crimeTypes": sorted(types.keys())
            })

    results.sort(key=lambda x: x["count"], reverse=True)

    return {
        "success": True,
        "data": results[:20]
    }


@app.get("/api/export/csv")
async def export_csv(
    user=Depends(require_roles("admin", "police", "analyst"))
):
    rows = [
        d async for d in db.crime_reports.find({}).sort("createdAt", -1)
    ]

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "referenceNo",
        "crime_type",
        "severity",
        "status",
        "area",
        "description",
        "longitude",
        "latitude",
        "source",
        "createdAt"
    ])

    for r in rows:
        lng, lat = r["location"]["coordinates"]

        writer.writerow([
            r.get("referenceNo", ""),
            r.get("crime_type", ""),
            r.get("severity", ""),
            r.get("status", ""),
            r.get("area", ""),
            r.get("description", ""),
            lng,
            lat,
            r.get("source", ""),
            r.get("createdAt", "")
        ])

    output.seek(0)

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=crime_reports.csv"
        }
    )
    # ============================================================
# SERVE FRONTEND DASHBOARD FROM BACKEND
# Open: http://127.0.0.1:5000
# ============================================================

from pathlib import Path as _SentinelPath
from fastapi.responses import FileResponse as _SentinelFileResponse

_SENTINEL_FRONTEND_INDEX = (
    _SentinelPath(__file__).resolve().parent.parent
    / "frontend"
    / "index.html"
)


@app.get("/")
async def sentinel_frontend_home():
    return _SentinelFileResponse(_SENTINEL_FRONTEND_INDEX)


@app.get("/index.html")
async def sentinel_frontend_index():
    return _SentinelFileResponse(_SENTINEL_FRONTEND_INDEX)
@app.get("/api/public/risk")
async def public_risk(days: int = Query(30, ge=1, le=365)):
    since = now_utc() - timedelta(days=days)

    pipeline = [
        {"$match": {"occurredAt": {"$gte": since}}},
        {
            "$group": {
                "_id": "$area",
                "count": {"$sum": 1},
                "avgLng": {"$avg": {"$arrayElemAt": ["$location.coordinates", 0]}},
                "avgLat": {"$avg": {"$arrayElemAt": ["$location.coordinates", 1]}},
                "crimeTypes": {"$addToSet": "$crime_type"},
                "criticalCount": {
                    "$sum": {"$cond": [{"$eq": ["$severity", "critical"]}, 1, 0]}
                },
                "highCount": {
                    "$sum": {"$cond": [{"$eq": ["$severity", "high"]}, 1, 0]}
                },
            }
        },
        {"$sort": {"count": -1}},
    ]

    rows = []
    async for r in db.crime_reports.aggregate(pipeline):
        count = int(r.get("count", 0))
        critical = int(r.get("criticalCount", 0))
        high = int(r.get("highCount", 0))

        if count >= 5 or critical >= 1 or high >= 3:
            risk = "HIGH"
        elif count >= 3 or high >= 1:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        rows.append({
            "area": r.get("_id") or "Unknown Area",
            "count": count,
            "latitude": float(r.get("avgLat") or 33.6844),
            "longitude": float(r.get("avgLng") or 73.0479),
            "riskLevel": risk,
            "crimeTypes": r.get("crimeTypes", []),
            "radiusMeters": 700 if risk == "HIGH" else 550 if risk == "MEDIUM" else 400,
        })

    return {
        "success": True,
        "data": rows,
        "summary": {
            "totalAreas": len(rows),
            "highRiskAreas": len([x for x in rows if x["riskLevel"] == "HIGH"]),
            "totalRecentReports": sum(x["count"] for x in rows),
        },
    }


@app.get("/api/public/track")
async def public_track(referenceNo: str, phone: Optional[str] = None):
    report = await db.crime_reports.find_one({"referenceNo": referenceNo.strip()})

    if not report:
        raise HTTPException(status_code=404, detail="Complaint reference not found")

    saved_phone = (report.get("reporter") or {}).get("phone") or ""
    if saved_phone and phone and saved_phone.strip() != phone.strip():
        raise HTTPException(status_code=403, detail="Phone number does not match this complaint")

    return {
        "success": True,
        "data": {
            "referenceNo": report.get("referenceNo"),
            "crime_type": report.get("crime_type"),
            "severity": report.get("severity"),
            "area": report.get("area"),
            "status": report.get("status"),
            "createdAt": report.get("createdAt").isoformat() if report.get("createdAt") else None,
            "updatedAt": report.get("updatedAt").isoformat() if report.get("updatedAt") else None,
        },
    }
