from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import os
import bcrypt

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL", "mongodb://127.0.0.1:27017")
DB_NAME = os.getenv("DB_NAME", "sentinel_crime_db")

client = MongoClient(MONGO_URL)
db = client[DB_NAME]


def now_utc():
    return datetime.now(timezone.utc)


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def crime(ref, crime_type, severity, area, description, lat, lng, days_ago, status="reported"):
    dt = now_utc() - timedelta(days=days_ago)
    return {
        "referenceNo": ref,
        "crime_type": crime_type,
        "severity": severity,
        "area": area,
        "description": description,
        "location": {
            "type": "Point",
            "coordinates": [lng, lat]
        },
        "status": status,
        "source": "seed_data",
        "reporter": {
            "name": "System Seed",
            "phone": ""
        },
        "occurredAt": dt,
        "createdAt": dt,
        "updatedAt": dt,
        "statusHistory": [
            {
                "status": status,
                "at": dt,
                "by": "seed"
            }
        ]
    }


def main():
    db.users.delete_many({})
    db.crime_reports.delete_many({})
    db.notifications.delete_many({})

    db.users.insert_many([
        {
            "name": "Admin User",
            "email": "admin@sentinel.local",
            "password": hash_password("Admin123"),
            "role": "admin",
            "createdAt": now_utc()
        },
        {
            "name": "Police Officer",
            "email": "police@sentinel.local",
            "password": hash_password("Police123"),
            "role": "police",
            "createdAt": now_utc()
        },
        {
            "name": "Crime Analyst",
            "email": "analyst@sentinel.local",
            "password": hash_password("Analyst123"),
            "role": "analyst",
            "createdAt": now_utc()
        }
    ])

    reports = [
        crime("SEN-SEED-001", "robbery", "critical", "Saddar Rawalpindi", "Armed robbery near market.", 33.5951, 73.0557, 1),
        crime("SEN-SEED-002", "theft", "medium", "Saddar Rawalpindi", "Mobile snatching reported.", 33.5958, 73.0562, 2),
        crime("SEN-SEED-003", "assault", "high", "Saddar Rawalpindi", "Street fight complaint.", 33.5949, 73.0548, 3),
        crime("SEN-SEED-004", "robbery", "high", "Saddar Rawalpindi", "Cash robbery complaint.", 33.5962, 73.0552, 4),
        crime("SEN-SEED-005", "theft", "low", "Saddar Rawalpindi", "Bike theft report.", 33.5944, 73.0568, 5),

        crime("SEN-SEED-006", "theft", "medium", "F-7 Islamabad", "Car mirror stolen.", 33.7295, 73.0479, 1),
        crime("SEN-SEED-007", "robbery", "high", "F-7 Islamabad", "Wallet snatching.", 33.7301, 73.0485, 2),
        crime("SEN-SEED-008", "fraud", "medium", "F-7 Islamabad", "Online fraud complaint.", 33.7288, 73.0491, 6),

        crime("SEN-SEED-009", "burglary", "high", "G-9 Islamabad", "House burglary.", 33.7089, 73.0678, 7),
        crime("SEN-SEED-010", "assault", "medium", "G-9 Islamabad", "Assault outside shop.", 33.7095, 73.0669, 9),
        crime("SEN-SEED-011", "vandalism", "low", "G-9 Islamabad", "Vehicle damage complaint.", 33.7078, 73.0681, 12),

        crime("SEN-SEED-012", "fraud", "medium", "Blue Area Islamabad", "Business fraud complaint.", 33.7251, 73.0431, 10),
        crime("SEN-SEED-013", "theft", "low", "Blue Area Islamabad", "Laptop bag stolen.", 33.7260, 73.0450, 11),

        crime("SEN-SEED-014", "robbery", "high", "Raja Bazar Rawalpindi", "Shop robbery.", 33.6015, 73.0498, 1),
        crime("SEN-SEED-015", "theft", "medium", "Raja Bazar Rawalpindi", "Pocket theft.", 33.6020, 73.0503, 3),
        crime("SEN-SEED-016", "assault", "medium", "Raja Bazar Rawalpindi", "Physical assault.", 33.6009, 73.0491, 4),

        crime("SEN-SEED-017", "kidnapping", "critical", "I-8 Islamabad", "Kidnapping attempt.", 33.6942, 73.0860, 8),
        crime("SEN-SEED-018", "burglary", "medium", "I-8 Islamabad", "Night burglary.", 33.6950, 73.0850, 14),

        crime("SEN-SEED-019", "vandalism", "low", "Bahria Town Rawalpindi", "Property vandalism.", 33.5300, 72.9254, 16),
        crime("SEN-SEED-020", "theft", "low", "Bahria Town Rawalpindi", "Minor theft.", 33.5285, 72.9270, 20),

        crime("SEN-SEED-021", "murder", "critical", "Lal Kurti Rawalpindi", "Murder case record.", 33.6025, 73.0622, 18, "investigating"),
        crime("SEN-SEED-022", "robbery", "high", "Lal Kurti Rawalpindi", "Robbery case.", 33.6010, 73.0610, 19),

        crime("SEN-SEED-023", "fraud", "medium", "Aabpara Islamabad", "Bank fraud complaint.", 33.6900, 73.0620, 21),
        crime("SEN-SEED-024", "theft", "medium", "Aabpara Islamabad", "Bag theft.", 33.6911, 73.0631, 22),
        crime("SEN-SEED-025", "assault", "high", "Aabpara Islamabad", "Assault complaint.", 33.6895, 73.0613, 23, "resolved")
    ]

    db.crime_reports.insert_many(reports)

    db.notifications.insert_one({
        "title": "System ready",
        "message": "Seed data loaded successfully.",
        "crimeId": "",
        "referenceNo": "",
        "read": False,
        "createdAt": now_utc()
    })

    db.crime_reports.create_index([("location", "2dsphere")])
    db.crime_reports.create_index([("crime_type", 1)])
    db.crime_reports.create_index([("severity", 1)])
    db.crime_reports.create_index([("status", 1)])
    db.crime_reports.create_index([("area", 1)])
    db.crime_reports.create_index([("occurredAt", -1)])
    db.users.create_index("email", unique=True)

    print("Seed completed successfully")
    print("Database:", DB_NAME)
    print("Users inserted: 3")
    print("Crime reports inserted:", len(reports))
    print("")
    print("Login accounts:")
    print("Admin   -> admin@sentinel.local / Admin123")
    print("Police  -> police@sentinel.local / Police123")
    print("Analyst -> analyst@sentinel.local / Analyst123")


if __name__ == "__main__":
    main()
    