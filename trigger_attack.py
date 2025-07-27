import os

file_path = "trigger_attack.txt"

try:
    with open(file_path, "w") as f:
        f.write("attack")  # Write something inside to confirm it's created
    print("✅ Attack triggered! File created successfully.")
except Exception as e:
    print(f"❌ Error: {e}")

# Verify if the file exists
if os.path.exists(file_path):
    print("✅ File exists: Success!")
else:
    print("❌ File was NOT created!")
