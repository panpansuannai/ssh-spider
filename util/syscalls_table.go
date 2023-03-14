package util

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func ParseSyscallsTBLFile(filePath string) (map[uint64]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
	}

	syscallsTable := make(map[uint64]string)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		words := strings.Fields(line)
		if len(words) <= 0 || words[0] == "#" {
			continue
		}
		syscallNum, err := strconv.Atoi(words[0])
		if err != nil {
			return nil, fmt.Errorf("ParseSyscallsTBLFile line(%s) word(%s) error: %w", line, words[0], err)
		}
		syscallsTable[uint64(syscallNum)] = words[2]
	}
	return syscallsTable, nil
}
