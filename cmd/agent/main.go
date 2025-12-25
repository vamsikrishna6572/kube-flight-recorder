package main

import (
    "log"

    "github.com/vamsikrishna6572/kube-flight-recorder/pkg/ebpf/hello"
)

func main() {
    log.Println("Starting Kube Flight Recorder: Hello eBPF Test...")
    if err := hello.Run(); err != nil {
        log.Fatalf("error: %v", err)
    }
}
