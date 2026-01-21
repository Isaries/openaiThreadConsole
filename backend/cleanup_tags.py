from app import create_app, db
from app.models import Tag

def cleanup_orphan_tags():
    app = create_app()
    with app.app_context():
        print("Checking for orphan tags...")
        tags = Tag.query.all()
        count = 0
        deleted_names = []
        
        for t in tags:
            # Check relationships
            # Note: accessing t.projects loads them due to lazy=True relationship
            if not t.projects:
                print(f"Found orphan tag: {t.name}")
                db.session.delete(t)
                deleted_names.append(t.name)
                count += 1
        
        if count > 0:
            db.session.commit()
            print(f"Cleanup Complete. Deleted {count} tags: {deleted_names}")
        else:
            print("No orphan tags found.")

if __name__ == "__main__":
    cleanup_orphan_tags()
