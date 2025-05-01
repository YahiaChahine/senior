import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { interval, Subscription } from 'rxjs';
import { switchMap } from 'rxjs/operators';

interface Process {
  pid: number;
  name: string;
  result: string; // "1" for threat, "0" for safe
  timestamp?: string;
}

interface Log {
  message: string;
  type: 'normal' | 'warning' | 'process';
  process?: Process; // Only for process logs
}

@Component({
  selector: 'app-console',
  standalone: true,
  imports: [CommonModule, FormsModule, HttpClientModule],
  templateUrl: './console.component.html',
  styleUrls: ['./console.component.scss']
})
export class ConsoleComponent implements OnInit, OnDestroy {
  username = '@Yahias';
  runningProcesses = 0;
  threatsDetected = 0;
  isRunning = false;
  logs: Log[] = [
    { message: 'System initialized...', type: 'normal' },
    { message: 'Waiting for connection...', type: 'normal' },
  ];
  private apiUrl = 'http://localhost:8000';
  private pollingSubscription!: Subscription;

  constructor(private http: HttpClient) {}

  ngOnInit() {
    this.checkSystemStatus();
  }

  ngOnDestroy() {
    if (this.pollingSubscription) {
      this.pollingSubscription.unsubscribe();
    }
  }

  toggleSystem() {
    if (this.isRunning) {
      this.stopSystem();
    } else {
      this.startSystem();
    }
  }

  startSystem() {
    this.http.post(`${this.apiUrl}/start`, {}).subscribe({
      next: (response: any) => {
        this.isRunning = true;
        this.addLog(`System STARTED at ${new Date().toLocaleTimeString()}`, 'normal');
        this.addLog(`Monitoring process PID: ${response.pid}`, 'normal');
        this.startPolling();
      },
      error: (error) => {
        this.addLog(`ERROR: Failed to start system - ${error.error.detail}`, 'warning');
      }
    });
  }

  stopSystem() {
    this.http.post(`${this.apiUrl}/stop`, {}).subscribe({
      next: (response: any) => {
        this.isRunning = false;
        this.addLog(`System STOPPED at ${new Date().toLocaleTimeString()}`, 'normal');
        response.killed_processes.forEach((proc: string) => {
          this.addLog(`Terminated: ${proc}`, 'normal');
        });
        if (this.pollingSubscription) {
          this.pollingSubscription.unsubscribe();
        }
      },
      error: (error) => {
        this.addLog(`ERROR: Failed to stop system - ${error.error.detail}`, 'warning');
      }
    });
  }

  startPolling() {
    this.pollingSubscription = interval(2000)
      .pipe(
        switchMap(() => this.http.get<{data: Process[]}>(`${this.apiUrl}/pid`))
      )
      .subscribe({
        next: (response) => {
          this.processData(response.data);
        },
        error: (error) => {
          this.addLog(`ERROR: Failed to fetch process data - ${error.message}`, 'warning');
        }
      });
  }

  processData(processes: Process[]) {
    this.runningProcesses = processes.length;
    const newThreats = processes.filter(p => p.result === '1').length;
    
    // Update threat count
    if (newThreats > this.threatsDetected) {
      this.threatsDetected = newThreats;
    }

    // Clear previous process logs
    this.logs = this.logs.filter(log => log.type !== 'process');
    
    // Add new process logs
    processes.forEach(process => {
      if(process.result === '1'){
        this.addLog(
          `${process.pid} - ${process.result === '1' ? 'THREAT' : 'safe'}`,
          'process',
          process
        );
      }
      
    });
  }

  checkSystemStatus() {
    this.http.get(`${this.apiUrl}/pid`).subscribe({
      next: (response: any) => {
        if (response.data && response.data.length > 0) {
          this.isRunning = true;
          this.startPolling();
          this.addLog('Reconnected to existing monitoring session', 'normal');
        }
      },
      error: () => {
        this.addLog('Backend server not responding', 'warning');
      }
    });
  }

  addLog(message: string, type: 'normal' | 'warning' | 'process' = 'normal', process?: Process) {
    this.logs.push({ message, type, process });
    // Keep only the last 50 logs
    if (this.logs.length > 50) {
      this.logs.shift();
    }
  }

  isThreat(process: Process | undefined): boolean {
    return process?.result === '1';
  }
}