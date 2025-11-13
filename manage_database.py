"""
Database Management Tool
Clear logs, view statistics, backup and restore data
"""

import sqlite3
import os
import shutil
from datetime import datetime

DB_FILE = "app_data.db"
BACKUP_DIR = "backups"

def get_connection():
    """Get database connection"""
    if not os.path.exists(DB_FILE):
        print(f"❌ Database file '{DB_FILE}' not found!")
        print("   Run 'python createuser.py' first to initialize the database.")
        return None
    return sqlite3.connect(DB_FILE)

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def show_statistics():
    """Display current database statistics"""
    conn = get_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    
    print_header("DATABASE STATISTICS")
    
    # Total logs
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]
    print(f"Total Attack Logs: {total_logs}")
    
    if total_logs == 0:
        print("\n📝 Database is empty - no logs to display")
        conn.close()
        return
    
    # Logs by type
    print("\nAttacks by Type:")
    cursor.execute("""
        SELECT type, COUNT(*) as count 
        FROM logs 
        GROUP BY type 
        ORDER BY count DESC
    """)
    for row in cursor.fetchall():
        attack_type, count = row
        print(f"  {attack_type:30s}: {count:4d}")
    
    # Top attacking IPs
    print("\nTop Attacking IPs:")
    cursor.execute("""
        SELECT ip, COUNT(*) as count 
        FROM logs 
        GROUP BY ip 
        ORDER BY count DESC 
        LIMIT 10
    """)
    for row in cursor.fetchall():
        ip, count = row
        print(f"  {ip:20s}: {count:4d} attacks")
    
    # Recent attacks
    print("\nMost Recent Attacks (last 5):")
    cursor.execute("""
        SELECT time, ip, type, path 
        FROM logs 
        ORDER BY id DESC 
        LIMIT 5
    """)
    for row in cursor.fetchall():
        time_str, ip, attack_type, path = row
        print(f"  [{time_str}] {attack_type:20s} from {ip:15s} -> {path}")
    
    # Date range
    cursor.execute("SELECT MIN(time), MAX(time) FROM logs")
    min_time, max_time = cursor.fetchone()
    if min_time and max_time:
        print(f"\nDate Range: {min_time} to {max_time}")
    
    conn.close()

def clear_all_logs():
    """Delete all attack logs from database"""
    conn = get_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    
    # Get current count
    cursor.execute("SELECT COUNT(*) FROM logs")
    count = cursor.fetchone()[0]
    
    if count == 0:
        print("\n📝 No logs to delete - database is already empty")
        conn.close()
        return
    
    print_header("CLEAR ALL LOGS")
    print(f"⚠️  WARNING: This will permanently delete {count} log entries!")
    print(f"⚠️  This action CANNOT be undone!")
    
    confirm = input("\nType 'DELETE' to confirm (or anything else to cancel): ")
    
    if confirm.strip() == "DELETE":
        cursor.execute("DELETE FROM logs")
        conn.commit()
        print(f"\n✅ Successfully deleted {count} log entries")
        print("📊 Dashboard will now show no attacks")
    else:
        print("\n❌ Operation cancelled - no logs were deleted")
    
    conn.close()

def clear_logs_by_type():
    """Delete logs of a specific attack type"""
    conn = get_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    
    # Show available types
    print_header("CLEAR LOGS BY TYPE")
    cursor.execute("SELECT DISTINCT type FROM logs ORDER BY type")
    types = [row[0] for row in cursor.fetchall()]
    
    if not types:
        print("📝 No logs in database")
        conn.close()
        return
    
    print("Available attack types:")
    for i, attack_type in enumerate(types, 1):
        cursor.execute("SELECT COUNT(*) FROM logs WHERE type = ?", (attack_type,))
        count = cursor.fetchone()[0]
        print(f"  {i}. {attack_type} ({count} entries)")
    
    try:
        choice = int(input(f"\nSelect type to delete (1-{len(types)}) or 0 to cancel: "))
        
        if choice == 0:
            print("❌ Operation cancelled")
            conn.close()
            return
        
        if 1 <= choice <= len(types):
            selected_type = types[choice - 1]
            
            cursor.execute("SELECT COUNT(*) FROM logs WHERE type = ?", (selected_type,))
            count = cursor.fetchone()[0]
            
            confirm = input(f"\n⚠️  Delete {count} entries of type '{selected_type}'? (yes/no): ")
            
            if confirm.lower() == 'yes':
                cursor.execute("DELETE FROM logs WHERE type = ?", (selected_type,))
                conn.commit()
                print(f"✅ Successfully deleted {count} '{selected_type}' entries")
            else:
                print("❌ Operation cancelled")
        else:
            print("❌ Invalid selection")
    
    except ValueError:
        print("❌ Invalid input")
    
    conn.close()

def clear_logs_by_ip():
    """Delete logs from a specific IP address"""
    conn = get_connection()
    if not conn:
        return
    
    print_header("CLEAR LOGS BY IP ADDRESS")
    
    # Show top IPs
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip, COUNT(*) as count 
        FROM logs 
        GROUP BY ip 
        ORDER BY count DESC 
        LIMIT 20
    """)
    
    ips = cursor.fetchall()
    if not ips:
        print("📝 No logs in database")
        conn.close()
        return
    
    print("Top attacking IPs:")
    for ip, count in ips:
        print(f"  {ip:20s}: {count:4d} attacks")
    
    ip_to_delete = input("\nEnter IP address to delete (or press Enter to cancel): ").strip()
    
    if not ip_to_delete:
        print("❌ Operation cancelled")
        conn.close()
        return
    
    cursor.execute("SELECT COUNT(*) FROM logs WHERE ip = ?", (ip_to_delete,))
    count = cursor.fetchone()[0]
    
    if count == 0:
        print(f"❌ No logs found for IP: {ip_to_delete}")
        conn.close()
        return
    
    confirm = input(f"\n⚠️  Delete {count} entries from {ip_to_delete}? (yes/no): ")
    
    if confirm.lower() == 'yes':
        cursor.execute("DELETE FROM logs WHERE ip = ?", (ip_to_delete,))
        conn.commit()
        print(f"✅ Successfully deleted {count} entries from {ip_to_delete}")
    else:
        print("❌ Operation cancelled")
    
    conn.close()

def backup_database():
    """Create a backup of the database"""
    if not os.path.exists(DB_FILE):
        print(f"❌ Database file '{DB_FILE}' not found!")
        return
    
    # Create backup directory if it doesn't exist
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    # Generate backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"app_data_backup_{timestamp}.db")
    
    print_header("BACKUP DATABASE")
    print(f"Creating backup: {backup_file}")
    
    try:
        shutil.copy2(DB_FILE, backup_file)
        file_size = os.path.getsize(backup_file)
        print(f"✅ Backup successful!")
        print(f"   File: {backup_file}")
        print(f"   Size: {file_size:,} bytes")
    except Exception as e:
        print(f"❌ Backup failed: {e}")

def restore_database():
    """Restore database from backup"""
    if not os.path.exists(BACKUP_DIR):
        print(f"❌ Backup directory '{BACKUP_DIR}' not found!")
        return
    
    # List available backups
    backups = [f for f in os.listdir(BACKUP_DIR) if f.endswith('.db')]
    
    if not backups:
        print(f"❌ No backup files found in '{BACKUP_DIR}'")
        return
    
    print_header("RESTORE DATABASE")
    print("Available backups:")
    
    backups.sort(reverse=True)  # Most recent first
    for i, backup in enumerate(backups, 1):
        backup_path = os.path.join(BACKUP_DIR, backup)
        size = os.path.getsize(backup_path)
        modified = datetime.fromtimestamp(os.path.getmtime(backup_path))
        print(f"  {i}. {backup}")
        print(f"     Created: {modified.strftime('%Y-%m-%d %H:%M:%S')}, Size: {size:,} bytes")
    
    try:
        choice = int(input(f"\nSelect backup to restore (1-{len(backups)}) or 0 to cancel: "))
        
        if choice == 0:
            print("❌ Operation cancelled")
            return
        
        if 1 <= choice <= len(backups):
            selected_backup = backups[choice - 1]
            backup_path = os.path.join(BACKUP_DIR, selected_backup)
            
            print(f"\n⚠️  WARNING: This will replace your current database!")
            confirm = input(f"Restore from '{selected_backup}'? (yes/no): ")
            
            if confirm.lower() == 'yes':
                # Backup current database first
                if os.path.exists(DB_FILE):
                    safety_backup = DB_FILE + ".before_restore"
                    shutil.copy2(DB_FILE, safety_backup)
                    print(f"📦 Current database backed up to: {safety_backup}")
                
                # Restore
                shutil.copy2(backup_path, DB_FILE)
                print(f"✅ Database restored successfully from {selected_backup}")
            else:
                print("❌ Operation cancelled")
        else:
            print("❌ Invalid selection")
    
    except ValueError:
        print("❌ Invalid input")

def export_logs_csv():
    """Export logs to CSV file"""
    conn = get_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM logs")
    count = cursor.fetchone()[0]
    
    if count == 0:
        print("📝 No logs to export")
        conn.close()
        return
    
    print_header("EXPORT LOGS TO CSV")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = f"attack_logs_{timestamp}.csv"
    
    print(f"Exporting {count} logs to: {csv_file}")
    
    try:
        cursor.execute("SELECT id, time, ip, type, payload, path, user_agent FROM logs ORDER BY id")
        
        with open(csv_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("ID,Time,IP,Type,Payload,Path,User_Agent\n")
            
            # Write data
            for row in cursor.fetchall():
                # Escape commas and quotes in CSV
                row_escaped = [str(field).replace('"', '""') for field in row]
                line = ','.join([f'"{field}"' for field in row_escaped])
                f.write(line + '\n')
        
        file_size = os.path.getsize(csv_file)
        print(f"✅ Export successful!")
        print(f"   File: {csv_file}")
        print(f"   Records: {count:,}")
        print(f"   Size: {file_size:,} bytes")
    
    except Exception as e:
        print(f"❌ Export failed: {e}")
    
    conn.close()

def main_menu():
    """Display main menu and handle user input"""
    while True:
        print_header("DATABASE MANAGEMENT TOOL")
        print("1. Show Statistics")
        print("2. Clear ALL Logs (⚠️  Dangerous!)")
        print("3. Clear Logs by Type")
        print("4. Clear Logs by IP Address")
        print("5. Backup Database")
        print("6. Restore Database")
        print("7. Export Logs to CSV")
        print("8. Exit")
        print("="*70)
        
        choice = input("\nSelect option (1-8): ").strip()
        
        if choice == '1':
            show_statistics()
        elif choice == '2':
            clear_all_logs()
        elif choice == '3':
            clear_logs_by_type()
        elif choice == '4':
            clear_logs_by_ip()
        elif choice == '5':
            backup_database()
        elif choice == '6':
            restore_database()
        elif choice == '7':
            export_logs_csv()
        elif choice == '8':
            print("\n👋 Goodbye!")
            break
        else:
            print("\n❌ Invalid option. Please select 1-8.")
        
        if choice in ['1', '2', '3', '4', '5', '6', '7']:
            input("\nPress ENTER to continue...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")