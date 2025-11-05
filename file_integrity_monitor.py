import os
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path
import smtplib
from email.mime.text import MIMEText

class FileIntegrityMonitor:
    def __init__(self, watch_folder="./secure_files", hash_db="hash_db.json", log_file="security.log"):
        self.watch_folder = Path(watch_folder)
        self.hash_db_file = hash_db
        self.log_file = log_file
        self.hash_db = {}
        
        # Buat folder jika belum ada
        self.watch_folder.mkdir(exist_ok=True)
        
        # Load hash database
        self._load_hash_db()
    
    def _load_hash_db(self):
        """Load hash database dari file JSON"""
        try:
            if os.path.exists(self.hash_db_file):
                with open(self.hash_db_file, 'r') as f:
                    self.hash_db = json.load(f)
                self._log("INFO", f"Hash database loaded: {len(self.hash_db)} files")
            else:
                self._log("INFO", "No existing hash database found, creating new one")
        except Exception as e:
            self._log("WARNING", f"Error loading hash database: {str(e)}")
    
    def _save_hash_db(self):
        """Simpan hash database ke file JSON"""
        try:
            with open(self.hash_db_file, 'w') as f:
                json.dump(self.hash_db, f, indent=2)
            self._log("INFO", f"Hash database saved: {len(self.hash_db)} files")
        except Exception as e:
            self._log("WARNING", f"Error saving hash database: {str(e)}")
    
    def _calculate_hash(self, file_path):
        """Hitung hash SHA256 dari file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self._log("WARNING", f"Error calculating hash for {file_path}: {str(e)}")
            return None
    
    def _log(self, level, message, file_name=None):
        """Catat log ke file dengan format yang ditentukan"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if file_name:
            log_message = f'[{timestamp}] {level}: File "{file_name}" {message}'
        else:
            log_message = f'[{timestamp}] {level}: {message}'
        
        # Tulis ke file log
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_message + '\n')
        except Exception as e:
            print(f"Error writing to log file: {str(e)}")
        
        # Juga print ke konsol
        print(log_message)
    
    def _send_alert(self, message):
        """Simulasi pengiriman alert (print ke konsol)"""
        print("\n" + "="*60)
        print("⚠️  SECURITY ALERT ⚠️")
        print(message)
        print("="*60 + "\n")
        
        # Untuk implementasi email sesungguhnya, uncomment kode berikut:
        """
        try:
            msg = MIMEText(message)
            msg['Subject'] = 'Security Alert - File Integrity Monitor'
            msg['From'] = 'monitor@example.com'
            msg['To'] = 'admin@example.com'
            
            # Konfigurasi SMTP server
            # s = smtplib.SMTP('localhost')
            # s.send_message(msg)
            # s.quit()
        except Exception as e:
            self._log("WARNING", f"Failed to send email alert: {str(e)}")
        """
    
    def initialize_baseline(self):
        """Buat baseline hash untuk semua file yang ada"""
        self._log("INFO", "Initializing baseline hash database...")
        
        file_count = 0
        for file_path in self.watch_folder.rglob('*'):
            if file_path.is_file():
                file_hash = self._calculate_hash(file_path)
                if file_hash:
                    relative_path = str(file_path.relative_to(self.watch_folder))
                    self.hash_db[relative_path] = {
                        'hash': file_hash,
                        'size': file_path.stat().st_size,
                        'modified': file_path.stat().st_mtime,
                        'created': datetime.now().isoformat()
                    }
                    file_count += 1
                    self._log("INFO", "added to baseline", relative_path)
        
        self._save_hash_db()
        self._log("INFO", f"Baseline initialized with {file_count} files")
        return file_count
    
    def check_integrity(self):
        """Periksa integritas file dan deteksi perubahan"""
        self._log("INFO", "Starting integrity check...")
        
        current_files = set()
        safe_files = 0
        corrupted_files = 0
        new_files = 0
        
        # Cek semua file yang ada saat ini
        for file_path in self.watch_folder.rglob('*'):
            if file_path.is_file():
                relative_path = str(file_path.relative_to(self.watch_folder))
                current_files.add(relative_path)
                
                current_hash = self._calculate_hash(file_path)
                if not current_hash:
                    continue
                
                # File baru (tidak ada di baseline)
                if relative_path not in self.hash_db:
                    self._log("ALERT", "detected (Unknown file)", relative_path)
                    self._send_alert(f'Unknown file detected: {relative_path}')
                    new_files += 1
                    
                    # Tambahkan ke database
                    self.hash_db[relative_path] = {
                        'hash': current_hash,
                        'size': file_path.stat().st_size,
                        'modified': file_path.stat().st_mtime,
                        'created': datetime.now().isoformat()
                    }
                
                # File sudah ada, cek integritasnya
                else:
                    stored_hash = self.hash_db[relative_path]['hash']
                    
                    if current_hash == stored_hash:
                        self._log("INFO", "verified OK", relative_path)
                        safe_files += 1
                    else:
                        self._log("WARNING", "integrity failed!", relative_path)
                        self._send_alert(f'File integrity failed: {relative_path}')
                        corrupted_files += 1
                        
                        # Update hash di database
                        self.hash_db[relative_path]['hash'] = current_hash
                        self.hash_db[relative_path]['modified'] = file_path.stat().st_mtime
        
        # Cek file yang dihapus
        deleted_files = 0
        baseline_files = set(self.hash_db.keys())
        missing_files = baseline_files - current_files
        
        for missing_file in missing_files:
            self._log("ALERT", "deleted (File missing)", missing_file)
            self._send_alert(f'File deleted: {missing_file}')
            deleted_files += 1
            del self.hash_db[missing_file]
        
        # Simpan perubahan
        self._save_hash_db()
        
        # Summary
        self._log("INFO", f"Integrity check completed - Safe: {safe_files}, Corrupted: {corrupted_files}, New: {new_files}, Deleted: {deleted_files}")
        
        return {
            'safe': safe_files,
            'corrupted': corrupted_files,
            'new': new_files,
            'deleted': deleted_files
        }
    
    def continuous_monitor(self, interval=60):
        """Monitor terus menerus dengan interval tertentu (dalam detik)"""
        self._log("INFO", f"Starting continuous monitoring (interval: {interval}s)")
        print(f"\n🔒 File Integrity Monitor Started")
        print(f"📁 Watching folder: {self.watch_folder.absolute()}")
        print(f"⏱️  Check interval: {interval} seconds")
        print(f"📋 Log file: {self.log_file}")
        print("\nPress Ctrl+C to stop...\n")
        
        try:
            while True:
                self.check_integrity()
                print(f"\n⏳ Next check in {interval} seconds...\n")
                time.sleep(interval)
        except KeyboardInterrupt:
            self._log("INFO", "Monitoring stopped by user")
            print("\n\n✅ Monitoring stopped gracefully")


def main():
    """Fungsi utama untuk menjalankan monitor"""
    import sys
    
    monitor = FileIntegrityMonitor()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "init":
            print("\n🔧 Initializing baseline...")
            count = monitor.initialize_baseline()
            print(f"\n✅ Baseline created for {count} files")
            
        elif command == "check":
            print("\n🔍 Running single integrity check...")
            results = monitor.check_integrity()
            print("\n📊 Results:")
            print(f"   ✅ Safe files: {results['safe']}")
            print(f"   ⚠️  Corrupted files: {results['corrupted']}")
            print(f"   🆕 New files: {results['new']}")
            print(f"   🗑️  Deleted files: {results['deleted']}")
            
        elif command == "monitor":
            interval = int(sys.argv[2]) if len(sys.argv) > 2 else 60
            monitor.continuous_monitor(interval)
            
        else:
            print("❌ Unknown command")
            print("\nUsage:")
            print("  python file_integrity_monitor.py init              - Initialize baseline")
            print("  python file_integrity_monitor.py check             - Run single check")
            print("  python file_integrity_monitor.py monitor [seconds] - Continuous monitoring")
    else:
        print("\n🔒 File Integrity Monitor")
        print("\nUsage:")
        print("  python file_integrity_monitor.py init              - Initialize baseline")
        print("  python file_integrity_monitor.py check             - Run single check")
        print("  python file_integrity_monitor.py monitor [seconds] - Continuous monitoring")
        print("\nExample:")
        print("  python file_integrity_monitor.py init")
        print("  python file_integrity_monitor.py check")
        print("  python file_integrity_monitor.py monitor 30")


if __name__ == "__main__":
    main()