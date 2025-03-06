from app import db

def init_db():
    # Import all models to ensure they are registered
    from app import User, Hostel, Room, RoomRequest, Notification
    from app import Complaint, ComplaintComment, ComplaintAttachment
    from app import Payment, Leave, MealPlan, MealPreference
    from app import Visitor, MaintenanceRecord, InventoryItem
    from app import ActivityLog, Announcement

    # Create all tables
    db.create_all()

if __name__ == '__main__':
    init_db()
