//! Shared real-process test support.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Captures one demonstration process and its readiness/output streams.
pub(crate) struct TestProcess {
    child: Child,
    #[allow(dead_code)]
    stdin: Option<ChildStdin>,
    pub(crate) ready: Receiver<String>,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    stdout_thread: Option<thread::JoinHandle<()>>,
    stderr_thread: Option<thread::JoinHandle<()>>,
}

impl TestProcess {
    /// Spawns a process with piped standard input and captured output.
    pub(crate) fn spawn(program: &str, args: &[String]) -> Self {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn demonstration process");
        let stdin = child.stdin.take();
        let stdout = Arc::new(Mutex::new(String::new()));
        let stderr = Arc::new(Mutex::new(String::new()));
        let (sender, ready) = mpsc::channel();
        let stdout_value = Arc::clone(&stdout);
        let stdout_pipe = child.stdout.take().expect("child stdout");
        let stdout_thread = thread::spawn(move || {
            for line in BufReader::new(stdout_pipe).lines() {
                let Ok(line) = line else { break };
                if line.starts_with("READY ") {
                    let _ = sender.send(line.clone());
                }
                if let Ok(mut output) = stdout_value.lock() {
                    output.push_str(&line);
                    output.push('\n');
                }
            }
        });
        let stderr_value = Arc::clone(&stderr);
        let stderr_pipe = child.stderr.take().expect("child stderr");
        let stderr_thread = thread::spawn(move || {
            for line in BufReader::new(stderr_pipe).lines() {
                let Ok(line) = line else { break };
                if let Ok(mut output) = stderr_value.lock() {
                    output.push_str(&line);
                    output.push('\n');
                }
            }
        });
        Self {
            child,
            stdin,
            ready,
            stdout,
            stderr,
            stdout_thread: Some(stdout_thread),
            stderr_thread: Some(stderr_thread),
        }
    }

    /// Writes one or more console commands to the process.
    #[allow(dead_code)]
    pub(crate) fn write_stdin(&mut self, commands: &[u8]) {
        self.stdin
            .as_mut()
            .expect("process stdin")
            .write_all(commands)
            .expect("write process stdin");
    }

    /// Waits for process exit up to `timeout`.
    pub(crate) fn wait_timeout(&mut self, timeout: Duration) -> ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("poll child") {
                self.join_readers();
                return status;
            }
            assert!(
                start.elapsed() < timeout,
                "child did not exit before timeout"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Waits until captured standard output contains `needle`.
    #[allow(dead_code)]
    pub(crate) fn wait_for_stdout(&self, needle: &str, timeout: Duration) -> String {
        let start = Instant::now();
        loop {
            let output = self.output().0;
            if output.contains(needle) {
                return output;
            }
            assert!(
                start.elapsed() < timeout,
                "process did not print {needle:?} before timeout; stdout: {output}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Terminates a process that is still running.
    pub(crate) fn kill(&mut self) {
        if self.child.try_wait().expect("poll child").is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.join_readers();
    }

    fn join_readers(&mut self) {
        if let Some(thread) = self.stdout_thread.take() {
            thread.join().expect("stdout reader");
        }
        if let Some(thread) = self.stderr_thread.take() {
            thread.join().expect("stderr reader");
        }
    }

    /// Returns captured standard output and standard error.
    pub(crate) fn output(&self) -> (String, String) {
        (
            self.stdout.lock().expect("stdout lock").clone(),
            self.stderr.lock().expect("stderr lock").clone(),
        )
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        self.kill();
    }
}
