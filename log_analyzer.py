import re
from datetime import datetime
from collections import Counter

class LogAnalyzer:
    def __init__(self, log_file="security.log"):
        self.log_file = log_file
        self.logs = []
        self._parse_logs()
    
    def _parse_logs(self):
        """Parse file log dan ekstrak informasi"""
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    match = re.match(r'\[(.*?)\] (.*?): (.*)', line.strip())
                    if match:
                        timestamp_str, level, message = match.groups()
                        try:
                            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        except:
                            timestamp = None
                        
                        self.logs.append({
                            'timestamp': timestamp,
                            'level': level,
                            'message': message,
                            'raw': line.strip()
                        })
        except FileNotFoundError:
            print(f"⚠️  Log file '{self.log_file}' not found!")
        except Exception as e:
            print(f"❌ Error parsing log: {str(e)}")
    
    def get_statistics(self):
        """Dapatkan statistik dari log"""
        if not self.logs:
            return None
        
        level_counts = Counter([log['level'] for log in self.logs])
        
        # Hitung file aman dan rusak
        safe_files = sum(1 for log in self.logs if 'verified OK' in log['message'])
        failed_files = sum(1 for log in self.logs if 'integrity failed' in log['message'])
        new_files = sum(1 for log in self.logs if 'Unknown file' in log['message'] or 'detected' in log['message'])
        deleted_files = sum(1 for log in self.logs if 'deleted' in log['message'] or 'missing' in log['message'])
        
        # Waktu terakhir anomali
        anomalies = [log for log in self.logs if log['level'] in ['WARNING', 'ALERT']]
        last_anomaly = anomalies[-1]['timestamp'] if anomalies else None
        
        return {
            'total_logs': len(self.logs),
            'level_counts': dict(level_counts),
            'safe_files': safe_files,
            'failed_files': failed_files,
            'new_files': new_files,
            'deleted_files': deleted_files,
            'last_anomaly': last_anomaly,
            'anomaly_count': len(anomalies)
        }
    
    def display_report(self):
        """Tampilkan laporan ke konsol"""
        stats = self.get_statistics()
        
        if not stats:
            print("❌ No logs to analyze")
            return
        
        print("\n" + "="*60)
        print("📊 SECURITY LOG ANALYSIS REPORT")
        print("="*60)
        
        print(f"\n📈 Overall Statistics:")
        print(f"   Total log entries: {stats['total_logs']}")
        print(f"   INFO: {stats['level_counts'].get('INFO', 0)}")
        print(f"   WARNING: {stats['level_counts'].get('WARNING', 0)}")
        print(f"   ALERT: {stats['level_counts'].get('ALERT', 0)}")
        
        print(f"\n📁 File Status:")
        print(f"   ✅ Safe files: {stats['safe_files']}")
        print(f"   ⚠️  Failed integrity: {stats['failed_files']}")
        print(f"   🆕 New files: {stats['new_files']}")
        print(f"   🗑️  Deleted files: {stats['deleted_files']}")
        
        print(f"\n🔍 Security Status:")
        print(f"   Total anomalies detected: {stats['anomaly_count']}")
        if stats['last_anomaly']:
            print(f"   Last anomaly: {stats['last_anomaly'].strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print(f"   Last anomaly: No anomalies detected")
        
        # Tampilkan log anomali terakhir
        print(f"\n⚠️  Recent Anomalies (last 5):")
        anomalies = [log for log in self.logs if log['level'] in ['WARNING', 'ALERT']]
        recent_anomalies = anomalies[-5:] if len(anomalies) > 0 else []
        
        if recent_anomalies:
            for log in reversed(recent_anomalies):
                print(f"   [{log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}] {log['level']}: {log['message']}")
        else:
            print("   No anomalies detected ✅")
        
        print("\n" + "="*60 + "\n")
    
    def get_logs_by_level(self, level):
        """Dapatkan semua log dengan level tertentu"""
        return [log for log in self.logs if log['level'] == level]
    
    def get_logs_by_date_range(self, start_date, end_date):
        """Dapatkan log dalam rentang tanggal tertentu"""
        return [log for log in self.logs 
                if log['timestamp'] and start_date <= log['timestamp'] <= end_date]


def main():
    import sys
    
    log_file = sys.argv[1] if len(sys.argv) > 1 else "security.log"
    
    analyzer = LogAnalyzer(log_file)
    analyzer.display_report()
    
    # Opsi untuk melihat detail
    print("Options:")
    print("1. View all ALERT logs")
    print("2. View all WARNING logs")
    print("3. Exit")
    
    try:
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == "1":
            alerts = analyzer.get_logs_by_level("ALERT")
            print(f"\n🚨 All ALERT logs ({len(alerts)}):")
            for log in alerts:
                print(f"   {log['raw']}")
        
        elif choice == "2":
            warnings = analyzer.get_logs_by_level("WARNING")
            print(f"\n⚠️  All WARNING logs ({len(warnings)}):")
            for log in warnings:
                print(f"   {log['raw']}")
    except:
        pass
    
    print("\n✅ Analysis complete\n")


if __name__ == "__main__":
    main()