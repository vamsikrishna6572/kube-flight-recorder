package syscalls

var Names = map[uint32]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	9:   "mmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	21:  "access",
	39:  "getpid",
	59:  "execve",
	62:  "kill",
	102: "socketcall",
	104: "setsockopt",
	107: "recvfrom",
	108: "sendmsg",
	109: "recvmsg",
	257: "openat",
	262: "newfstatat",
	273: "pread64",
}
