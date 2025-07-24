import sys
import time

class ProgressTracker:
    def __init__(self, total_checks):
        self.total_checks = total_checks
        self.current_check = 0
        self.start_time = time.time()
        self.check_times = {}
        
    def update_progress(self, check_name, status='running'):
        """Update progress with incremental numbering, check description, and completion status"""
        self.current_check += 1
        percent = int((self.current_check / self.total_checks) * 100)
        
        # Create progress bar
        bar_length = 30
        filled_length = int(bar_length * self.current_check // self.total_checks)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        # Status indicators
        status_icons = {
            'running': '🔄',
            'complete': '✅',
            'error': '❌',
            'warning': '⚠️',
            'skipped': '⏭️'
        }
        
        # Show current check and overall progress
        status_icon = status_icons.get(status, '🔄')
        elapsed_time = time.time() - self.start_time
        
        # Format elapsed time
        if elapsed_time < 60:
            time_str = f"{elapsed_time:.1f}s"
        elif elapsed_time < 3600:
            time_str = f"{elapsed_time/60:.1f}m"
        else:
            time_str = f"{elapsed_time/3600:.1f}h"
        
        # Estimate remaining time
        if self.current_check > 1:
            avg_time_per_check = elapsed_time / (self.current_check - 1)
            remaining_checks = self.total_checks - self.current_check
            estimated_remaining = avg_time_per_check * remaining_checks
            
            if estimated_remaining < 60:
                eta_str = f"{estimated_remaining:.1f}s"
            elif estimated_remaining < 3600:
                eta_str = f"{estimated_remaining/60:.1f}m"
            else:
                eta_str = f"{estimated_remaining/3600:.1f}h"
        else:
            eta_str = "calculating..."
        
        # Display progress
        sys.stdout.write(f"\r{status_icon} [{self.current_check}/{self.total_checks}] {check_name}... {bar} {percent}% | ⏱️ {time_str} | ⏳ ETA: {eta_str}")
        sys.stdout.flush()
        
        # Store check start time
        self.check_times[check_name] = time.time()

    def complete_check(self, check_name, status='complete'):
        """Mark a check as completed with status"""
        percent = int((self.current_check / self.total_checks) * 100)
        
        # Create progress bar
        bar_length = 30
        filled_length = int(bar_length * self.current_check // self.total_checks)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        # Status indicators
        status_icons = {
            'complete': '✅',
            'error': '❌',
            'warning': '⚠️',
            'skipped': '⏭️'
        }
        
        # Calculate check duration
        check_duration = 0
        if check_name in self.check_times:
            check_duration = time.time() - self.check_times[check_name]
        
        # Show completed check
        status_icon = status_icons.get(status, '✅')
        elapsed_time = time.time() - self.start_time
        
        # Format times
        if elapsed_time < 60:
            time_str = f"{elapsed_time:.1f}s"
        else:
            time_str = f"{elapsed_time/60:.1f}m"
            
        if check_duration < 60:
            duration_str = f"{check_duration:.1f}s"
        else:
            duration_str = f"{check_duration/60:.1f}m"
        
        sys.stdout.write(f"\r{status_icon} [{self.current_check}/{self.total_checks}] {check_name}... {bar} {percent}% | ⏱️ {time_str} | ⏱️ Check: {duration_str}")
        sys.stdout.flush()
        
        # Move to next line for next check
        print()

    def start_check(self, check_name):
        """Start a new check"""
        self.update_progress(check_name, 'running')

    def finish_check(self, check_name, status='complete'):
        """Finish a check with status"""
        self.complete_check(check_name, status)

    def get_summary(self):
        """Get progress summary"""
        elapsed_time = time.time() - self.start_time
        if elapsed_time < 60:
            time_str = f"{elapsed_time:.1f} seconds"
        elif elapsed_time < 3600:
            time_str = f"{elapsed_time/60:.1f} minutes"
        else:
            time_str = f"{elapsed_time/3600:.1f} hours"
            
        return {
            'completed': self.current_check,
            'total': self.total_checks,
            'percentage': int((self.current_check / self.total_checks) * 100),
            'elapsed_time': time_str
        } 