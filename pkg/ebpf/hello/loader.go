package hello

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/vamsikrishna6572/kube-flight-recorder/pkg/processor"
)

//
// Phase-2 enhancement: syscall number → syscall name lookup.
// We will use this in processor shortly.
//
var syscallNames = map[uint64]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	17:  "pread64",
	21:  "access",
	39:  "getpid",
	59:  "execve",
	62:  "kill",
	102: "pselect6",
	104: "set_robust_list",
	107: "utimensat",
	108: "fallocate",
	109: "set_tid_address",
	257: "openat",
	262: "newfstatat",
	273: "setresgid",
}

//
// Run loads the eBPF programs and attaches all crash + syscall hooks.
//
func Run() error {
	// Allow unlimited locked memory for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("rlimit: %v", err)
	}

	// Load programs & maps
	objs := struct {
		HandleSysEnter *ebpf.Program `ebpf:"handle_sys_enter"`
		HandleSignal   *ebpf.Program `ebpf:"handle_signal"`
		HandleExit     *ebpf.Program `ebpf:"handle_exit"`
		Flight         *ebpf.Map     `ebpf:"flight"`
	}{}

	// Load BPF object
	spec, err := ebpf.LoadCollectionSpec("hello_bpf.o")
	if err != nil {
		return fmt.Errorf("spec load: %v", err)
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("assign: %v", err)
	}

	defer objs.HandleSysEnter.Close()
	defer objs.HandleSignal.Close()
	defer objs.HandleExit.Close()

	//
	// Attach: sys_enter — records rolling buffer per PID
	//
	sysEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.HandleSysEnter, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter: %v", err)
	}
	defer sysEnter.Close()

	//
	// Attach: signal_deliver — detect SIGKILL / SIGSEGV
	//
	signalHook, err := link.Tracepoint("signal", "signal_deliver", objs.HandleSignal, nil)
	if err != nil {
		return fmt.Errorf("attach signal: %v", err)
	}
	defer signalHook.Close()

	//
	// Attach: sched_process_exit — detect crash on exit
	//
	exitHook, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		return fmt.Errorf("attach sched exit: %v", err)
	}
	defer exitHook.Close()

	log.Println("Starting Kube Flight Recorder: Hello eBPF Test...")
	log.Println("Flight Recorder attached. Kernel now records last syscalls per PID.")
	log.Println("Crash-freeze monitoring enabled (SIGKILL / SIGSEGV / abnormal exit).")
	log.Println("No user logs — evidence lives in kernel flight buffer until extraction.")

	//
	// Continuous Extraction Loop
	//
	for {
		if err := processor.ExtractFrozen(objs.Flight); err != nil {
			log.Printf("extract error: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
}
