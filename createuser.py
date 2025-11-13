from database import init_db, create_user

if __name__ == '__main__':
    init_db()
    username = "test"
    password = "1234"   # change to stronger password for real projects
    try:
        create_user(username, password)
        print(f"Created user: {username} / {password}")
    except Exception as e:
        print("Could not create user (maybe already exists):", e)
