from app import create_app
from app.models import RefreshHistory
import json
import datetime

def check_refresh_errors():
    app = create_app()
    with app.app_context():
        # Query for failed or partial executions
        records = RefreshHistory.query.filter(
            RefreshHistory.result_status.in_(['Critical Failed', 'Partial', 'Failed'])
        ).order_by(RefreshHistory.timestamp.desc()).limit(5).all()

        print(f"Found {len(records)} recent error records:")
        print("-" * 50)

        for record in records:
            time_str = datetime.datetime.fromtimestamp(record.timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Time: {time_str}")
            print(f"Status: {record.result_status}")
            print(f"Duration: {record.duration}s")
            print(f"Scanned: {record.total_scanned}, Updated: {record.updated_count}, Errors: {record.error_count}")
            
            if record.log_json:
                try:
                    logs = json.loads(record.log_json)
                    print("Error Details:")
                    if isinstance(logs, list):
                        for log in logs:
                            print(f"  - {log}")
                    else:
                        print(f"  {logs}")
                except json.JSONDecodeError:
                    print(f"  Raw Log: {record.log_json}")
            else:
                print("  No detailed logs available.")
            
            print("-" * 50)

if __name__ == "__main__":
    check_refresh_errors()
