// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"
)

var (
	flagLLMEnabled        = flag.Bool("llm_api_enabled", false, "是否启用LLM API")
	flagLLMAPIURL         = flag.String("llm_api_url", "http://100.64.88.112:5231", "LLM API URL地址")
	flagLLMStallThreshold = flag.Int("llm_stall_threshold", 1000, "LLM停滞阈值")
	flagLLMUsageFrequency = flag.Int("llm_usage_frequency", 10, "LLM使用频率百分比")
)

func main() {
	flag.Parse()

	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "用法: syz-runner <index> <manager-addr> <manager-port>")
		os.Exit(1)
	}

	// 设置环境变量
	if *flagLLMEnabled {
		os.Setenv("SYZ_LLM_ENABLED", "1")
		os.Setenv("SYZ_LLM_API_URL", *flagLLMAPIURL)
		os.Setenv("SYZ_LLM_STALL_THRESHOLD", strconv.Itoa(*flagLLMStallThreshold))
		os.Setenv("SYZ_LLM_USAGE_FREQUENCY", strconv.Itoa(*flagLLMUsageFrequency))
		os.Setenv("SYZ_LLM_USE_OPENAI_FORMAT", "1")

		log.Printf("LLM API 已启用: URL=%s, 阈值=%d, 频率=%d%%",
			*flagLLMAPIURL, *flagLLMStallThreshold, *flagLLMUsageFrequency)
	}

	// 查找syz-executor路径
	executorPath := os.Getenv("PATH")
	if executorPath == "" {
		executorPath = "syz-executor"
	}

	// 构建新的参数数组，传递给syz-executor
	args := []string{"runner"}
	args = append(args, os.Args[1:]...) // 添加index, manager-addr, manager-port

	// 执行syz-executor
	err := execExecutor(executorPath, args)
	if err != nil {
		log.Fatalf("执行syz-executor失败: %v", err)
	}
}

func execExecutor(path string, args []string) error {
	log.Printf("执行: %s %v", path, args)
	return syscallExec(path, append([]string{path}, args...), os.Environ())
}

// syscallExec is a wrapper for syscall.Exec to make it mockable for testing
var syscallExec = syscall.Exec
