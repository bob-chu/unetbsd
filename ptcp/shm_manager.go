package main

/*
#include "stats_cgo.h"
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

)

const (
	shmPathEnvVar    = "UNETBSD_SHM_PATH"
	instanceIDEnvVar = "UNETBSD_INSTANCE_ID"
	shmSizeEnvVar    = "UNETBSD_SHM_SIZE"
)



// GetStatsSize returns the size of the C.struct_stats_t in bytes.
func GetStatsSize() uintptr {
	return uintptr(C.sizeof_stats_t)
}

// CreateSharedMemory creates and maps a shared memory segment from a regular file.
func CreateSharedMemory(filePath string, totalSize uintptr) ([]byte, int, error) {
	// Create or open the regular file
	f, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return nil, 0, fmt.Errorf("os.OpenFile failed: %w", err)
	}
	fd := int(f.Fd())

	// Set the size of the file
	if err := syscall.Ftruncate(fd, int64(totalSize)); err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("Ftruncate failed: %w", err)
	}

	// Map the file into the address space
	data, err := syscall.Mmap(fd, 0, int(totalSize), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("Mmap failed: %w", err)
	}

	// Close the file descriptor, as mmap holds a reference
	f.Close()

	// Zero out the memory
	for i := range data {
		data[i] = 0
	}

	return data, fd, nil
}

// MapSharedMemory maps an existing shared memory segment from a regular file.
func MapSharedMemory(filePath string, totalSize uintptr) ([]byte, int, error) {
	f, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("os.OpenFile failed: %w", err)
	}
	fd := int(f.Fd())

	data, err := syscall.Mmap(fd, 0, int(totalSize), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("Mmap failed: %w", err)
	}
	f.Close() // Close the file descriptor after mapping
	return data, fd, nil
}

// UnmapSharedMemory unmaps the shared memory segment.
func UnmapSharedMemory(data []byte) error {
	return syscall.Munmap(data)
}

// UnlinkSharedMemory removes the backing file for the shared memory object.
func UnlinkSharedMemory(filePath string) error {
	return os.Remove(filePath)
}

// GetShmPath generates a path for the shared memory backing file.
func GetShmPath() string {
	// Using a path in /dev/shm for better performance (tmpfs)
	// or os.TempDir() for a more general temporary file.
	// For this context, /dev/shm is usually preferred for shared memory files.
	return filepath.Join("/dev/shm", fmt.Sprintf("unetbsd_perf_shm_%d.tmp", os.Getpid()))
}

// ParseStatsFromShm parses the shared memory byte slice into a slice of C.struct_stats_t structs.
func ParseStatsFromShm(shmBytes []byte, totalInstances int) ([]C.struct_stats_t, error) {
	stats := make([]C.struct_stats_t, totalInstances)
	statsSize := GetStatsSize()

	for i := 0; i < totalInstances; i++ {
		offset := uintptr(i) * statsSize
		if offset+statsSize > uintptr(len(shmBytes)) {
			return nil, fmt.Errorf("shared memory too small for instance %d", i)
		}
		
		// Use unsafe.Pointer to convert a byte slice to a *C.struct_stats_t pointer
		// Then dereference it to copy the data into the C.struct_stats_t struct
		statsPtr := (*C.struct_stats_t)(unsafe.Pointer(&shmBytes[offset]))
		stats[i] = *statsPtr
	}
	return stats, nil
}