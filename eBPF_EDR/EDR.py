from bcc import BPF
import ctypes

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char argv[160];
    int is_blocked;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.is_blocked = 0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    const char __user *const __user *args_ptr = (const char __user *const __user *)args->argv;
    const char __user *argp;
    char check_cmd[16];
    bpf_probe_read_user(&argp, sizeof(argp), &args_ptr[0]);
    bpf_probe_read_user_str(&check_cmd, sizeof(check_cmd), argp);
    if (check_cmd[0] == 'p' && check_cmd[1] == 'i' &&
        check_cmd[2] == 'n' && check_cmd[3] == 'g') {
        bpf_send_signal(9);
        data.is_blocked = 1;
    }
    if (check_cmd[0] == 'n' && check_cmd[1] == 'c' &&
        check_cmd[2] == 'a' && check_cmd[3] == 't') {
        bpf_send_signal(9);
        data.is_blocked = 1;
    }

    if (argp) {
        bpf_probe_read_user_str(&data.argv, sizeof(data.argv), argp);
    }

    int len = 0;
    #pragma unroll
    for (int i = 0;i < 160;i++) {
        if (data.argv[i] == 0) {
            len = i;
            break;
        }
    }

    if (len < 159) {
        data.argv[len] = ' ';
        len++;
    }

    bpf_probe_read_user(&argp, sizeof(argp), &args_ptr[1]);
    if (argp) {
        bpf_probe_read_user_str(&data.argv[len], sizeof(data.argv) - len, argp);
    }

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=bpf_source)
print(f"{'PID':<6} {'COMM':<16} {'ARGs'}")
print("="*50)

ignore_list = [
    "cpuUsage.sh", "xfce4-panel-gen", "wrapper-2.0", "sh", "grep", "cut", "sed", "tr", "cat", "sleep"
]
def print_event(cpu, data, size):
    event = b["events"].event(data)
    comm = event.comm.decode('utf-8', 'replace')
    args = event.argv.decode('utf-8', 'replace')
    if comm in ignore_list:
        return
    raw_args = event.argv.decode('utf-8', 'replace')
    if event.is_blocked == 1:
        status = "Blocked"
    else:
        status = "Allowed"
    if "/etc/shadow" in args:
        print(f"ALERT: Process {comm} (PID {event.pid}) attempted to access /etc/shadow")
        print(f"culprit: {comm}")
        print(f"command: {args}")
    else:
        print(f"{event.pid:<6} {comm:<16} {args}")
    print(f"{event.pid:<6} {comm:<16} {raw_args}")

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()