#!/usr/bin/env python3
"""
Script Demo untuk Testing File Integrity Monitor
Otomatis membuat file test dan melakukan simulasi serangan
"""

import os
import time
import random
import string
from pathlib import Path

class DemoTester:
    def __init__(self, test_folder="./secure_files"):
        self.test_folder = Path(test_folder)
        self.test_folder.mkdir(exist_ok=True)
    
    def random_string(self, length=50):
        """Generate random string"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def create_test_files(self, count=5):
        """Buat file-file test"""
        print("\n" + "="*60)
        print("📁 Creating Test Files")
        print("="*60)
        
        for i in range(1, count + 1):
            filename = f"testfile_{i}.txt"
            filepath = self.test_folder / filename
            
            content = f"Test File {i}\n"
            content += f"Created at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            content += f"Random data: {self.random_string()}\n"
            
            with open(filepath, 'w') as f:
                f.write(content)
            
            print(f"✅ Created: {filename}")
        
        # Buat beberapa file konfigurasi dummy
        config_files = {
            "config.json": '{\n  "app_name": "SecureApp",\n  "version": "1.0",\n  "debug": false\n}',
            "database.conf": "host=localhost\nport=5432\nuser=admin\npassword=secret123",
            "settings.ini": "[general]\ntheme=dark\nlanguage=en\n\n[security]\nencryption=AES256"
        }
        
        for filename, content in config_files.items():
            filepath = self.test_folder / filename
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"✅ Created: {filename}")
        
        print(f"\n✅ Total {count + len(config_files)} test files created")
    
    def simulate_file_modification(self):
        """Simulasi modifikasi file"""
        print("\n" + "="*60)
        print("⚠️  Simulating File Modification Attack")
        print("="*60)
        
        files = list(self.test_folder.glob("*.txt"))
        if not files:
            print("❌ No files to modify")
            return
        
        target_file = random.choice(files)
        print(f"🎯 Target: {target_file.name}")
        
        # Ubah isi file
        with open(target_file, 'a') as f:
            f.write(f"\n\n[MODIFIED] {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Malicious content: {self.random_string()}\n")
        
        print(f"✅ File modified: {target_file.name}")
        print("💡 This should trigger a WARNING in the integrity check")
    
    def simulate_malicious_file(self):
        """Simulasi penambahan file berbahaya"""
        print("\n" + "="*60)
        print("🚨 Simulating Malicious File Addition")
        print("="*60)
        
        malicious_files = [
            ("backdoor.php", "<?php system($_GET['cmd']); ?>"),
            ("malware.js", "eval(atob('ZXZpbChhdG9iKCk='))"),
            ("exploit.sh", "#!/bin/bash\nrm -rf /"),
            ("keylogger.py", "import keyboard\nkeyboard.record()"),
            ("hacked.txt", "Your files have been encrypted! Pay 1 BTC to recover.")
        ]
        
        filename, content = random.choice(malicious_files)
        filepath = self.test_folder / filename
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        print(f"🎯 Malicious file added: {filename}")
        print(f"📄 Content: {content[:50]}...")
        print("💡 This should trigger an ALERT in the integrity check")
    
    def simulate_file_deletion(self):
        """Simulasi penghapusan file"""
        print("\n" + "="*60)
        print("🗑️  Simulating File Deletion")
        print("="*60)
        
        files = list(self.test_folder.glob("config.json"))
        if not files:
            files = list(self.test_folder.glob("*.txt"))
        
        if not files:
            print("❌ No files to delete")
            return
        
        target_file = random.choice(files)
        print(f"🎯 Target: {target_file.name}")
        
        os.remove(target_file)
        
        print(f"✅ File deleted: {target_file.name}")
        print("💡 This should trigger an ALERT in the integrity check")
    
    def simulate_mass_modification(self):
        """Simulasi modifikasi massal (ransomware-like)"""
        print("\n" + "="*60)
        print("💀 Simulating Mass Modification (Ransomware)")
        print("="*60)
        
        files = list(self.test_folder.glob("*.txt"))
        modified_count = 0
        
        for file in files:
            with open(file, 'a') as f:
                f.write("\n\n=== ENCRYPTED BY RANSOMWARE ===\n")
                f.write("Send 5 BTC to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n")
            modified_count += 1
            print(f"💀 Encrypted: {file.name}")
        
        print(f"\n✅ Total {modified_count} files encrypted")
        print("💡 This should trigger multiple WARNINGs")
    
    def clean_test_files(self):
        """Hapus semua file test"""
        print("\n" + "="*60)
        print("🧹 Cleaning Test Files")
        print("="*60)
        
        count = 0
        for file in self.test_folder.glob("*"):
            if file.is_file():
                os.remove(file)
                count += 1
                print(f"🗑️  Deleted: {file.name}")
        
        print(f"\n✅ Total {count} files cleaned")


def main():
    import sys
    
    tester = DemoTester()
    
    print("\n" + "="*60)
    print("🧪 File Integrity Monitor - Demo & Testing Tool")
    print("="*60)
    print("\nAvailable Commands:")
    print("  1. setup          - Create test files")
    print("  2. modify         - Simulate file modification")
    print("  3. malicious      - Simulate malicious file addition")
    print("  4. delete         - Simulate file deletion")
    print("  5. ransomware     - Simulate mass modification")
    print("  6. full-demo      - Run complete attack simulation")
    print("  7. clean          - Clean all test files")
    print("  8. exit           - Exit")
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
    else:
        print("\nUsage: python demo_test.py [command]")
        print("Example: python demo_test.py setup")
        return
    
    if command == "setup" or command == "1":
        tester.create_test_files()
        print("\n💡 Next step: Run 'python file_integrity_monitor.py init'")
    
    elif command == "modify" or command == "2":
        tester.simulate_file_modification()
        print("\n💡 Next step: Run 'python file_integrity_monitor.py check'")
    
    elif command == "malicious" or command == "3":
        tester.simulate_malicious_file()
        print("\n💡 Next step: Run 'python file_integrity_monitor.py check'")
    
    elif command == "delete" or command == "4":
        tester.simulate_file_deletion()
        print("\n💡 Next step: Run 'python file_integrity_monitor.py check'")
    
    elif command == "ransomware" or command == "5":
        tester.simulate_mass_modification()
        print("\n💡 Next step: Run 'python file_integrity_monitor.py check'")
    
    elif command == "full-demo" or command == "6":
        print("\n🎬 Running Full Attack Simulation Demo")
        print("=" * 60)
        
        # Step 1: Create files
        tester.create_test_files()
        print("\n⏳ Waiting 2 seconds...")
        time.sleep(2)
        
        # Step 2: Modify a file
        tester.simulate_file_modification()
        print("\n⏳ Waiting 2 seconds...")
        time.sleep(2)
        
        # Step 3: Add malicious file
        tester.simulate_malicious_file()
        print("\n⏳ Waiting 2 seconds...")
        time.sleep(2)
        
        # Step 4: Delete a file
        tester.simulate_file_deletion()
        
        print("\n" + "="*60)
        print("✅ Full Demo Complete!")
        print("="*60)
        print("\n💡 Now run the following commands:")
        print("   1. python file_integrity_monitor.py init")
        print("   2. python demo_test.py modify")
        print("   3. python file_integrity_monitor.py check")
        print("   4. python log_analyzer.py")
    
    elif command == "clean" or command == "7":
        confirm = input("\n⚠️  This will delete all files in secure_files/. Continue? (y/n): ")
        if confirm.lower() == 'y':
            tester.clean_test_files()
            
            # Also clean hash_db and logs
            if os.path.exists("hash_db.json"):
                os.remove("hash_db.json")
                print("🗑️  Deleted: hash_db.json")
            if os.path.exists("security.log"):
                os.remove("security.log")
                print("🗑️  Deleted: security.log")
        else:
            print("❌ Cancelled")
    
    else:
        print(f"❌ Unknown command: {command}")
        print("Run 'python demo_test.py' to see available commands")


if __name__ == "__main__":
    main()