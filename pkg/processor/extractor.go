package processor

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vamsikrishna6572/kube-flight-recorder/pkg/util/syscalls"
)

const (
	MaxEvents = 256
)

// MUST MATCH BPF STRUCT EXACTLY
type Event struct {
	PID     uint32 `json:"pid"`
	Syscall uint32 `json:"syscall"`
	TS      uint64 `json:"timestamp_ns"`
}

// MUST MATCH BPF STRUCT EXACTLY
type FlightBuffer struct {
	Events [MaxEvents]Event
	Index  uint32
	Frozen uint32
}

// Final Output Struct
type OutputEvent struct {
	PID          uint32 `json:"pid"`
	Syscall      uint32 `json:"syscall"`
	SyscallName  string `json:"syscall_name"`
	TimestampNS  uint64 `json:"timestamp_ns"`
	TimestampISO string `json:"timestamp_human"`
}

func ExtractFrozen(flight *ebpf.Map) error {
	iter := flight.Iterate()

	var pid uint32
	var buf FlightBuffer

	for iter.Next(&pid, &buf) {
		if buf.Frozen == 0 {
			continue
		}

		log.Printf("[EXTRACT] Found frozen buffer for PID %d", pid)

		raw := reorder(buf)
		if len(raw) == 0 {
			continue
		}

		out := make([]OutputEvent, 0, len(raw))

		for _, e := range raw {
			name, ok := syscalls.Names[e.Syscall]
			if !ok {
				name = fmt.Sprintf("syscall_%d", e.Syscall)
			}

			out = append(out, OutputEvent{
				PID:          e.PID,
				Syscall:      e.Syscall,
				SyscallName:  name,
				TimestampNS:  e.TS,
				TimestampISO: time.Unix(0, int64(e.TS)).UTC().Format(time.RFC3339Nano),
			})
		}

		if err := saveReport(pid, out); err != nil {
			log.Printf("[ERROR] saving report pid %d: %v", pid, err)
		} else {
			log.Printf("[SAVED] crash report stored for pid %d", pid)
		}

		flight.Delete(&pid)
	}

	return iter.Err()
}

// Reorder cyclic buffer in correct order
func reorder(buf FlightBuffer) []Event {
	result := []Event{}

	start := buf.Index
	if start > MaxEvents {
		start = MaxEvents
	}

	for i := uint32(0); i < start; i++ {
		idx := (buf.Index + i) % MaxEvents
		ev := buf.Events[idx]
		if ev.PID == 0 {
			continue
		}
		result = append(result, ev)
	}

	return result
}

func saveReport(pid uint32, events []OutputEvent) error {

	procName := readLink(fmt.Sprintf("/proc/%d/exe", pid))
	cmdline := readCmdline(pid)
	host, _ := os.Hostname()

	report := map[string]interface{}{
		"pid":        pid,
		"process":    procName,
		"cmdline":    cmdline,
		"hostname":   host,
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"events":     events,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("json: %w", err)
	}

	if err := os.MkdirAll("/var/lib/kube-flight-recorder/reports", 0755); err != nil {
		return err
	}

	filename := fmt.Sprintf(
		"/var/lib/kube-flight-recorder/reports/%d_%d.json",
		pid,
		time.Now().UnixNano(),
	)

	return os.WriteFile(filename, data, 0644)
}

func readLink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return "unknown"
	}
	return target
}

func readCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "unknown"
	}

	for i := range data {
		if data[i] == 0 {
			data[i] = ' '
		}
	}

	return string(data)
}
