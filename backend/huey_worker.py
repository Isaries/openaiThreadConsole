from app.extensions import huey
import app.tasks  # Crucial: Register tasks with the huey instance

# Check if tasks are registered
# print(f"Registered tasks: {huey.registry._registry}")
