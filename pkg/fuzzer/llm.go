// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/prog"
)

var (
	// 用于解析LLM输出中的操作指令的正则表达式
	addRegex     = regexp.MustCompile(`<ADD pos=(\d+) call='([^']+)'/>`)
	deleteRegex  = regexp.MustCompile(`<DELETE pos=(\d+) call='([^']+)'/>`)
	replaceRegex = regexp.MustCompile(`<REPLACE pos=(\d+) old_call='([^']+)' new_call='([^']+)'/>`)
)

// LLM API 变异操作类型
const (
	LLMOpAdd     = "ADD"
	LLMOpDelete  = "DELETE"
	LLMOpReplace = "REPLACE"
)

// LLMRequest 表示发送到LLM API的请求
type LLMRequest struct {
	Instruction string `json:"instruction"`
	Input       string `json:"input"`
}

// LLMResponse 表示从LLM API接收到的响应
type LLMResponse struct {
	Output string `json:"output"`
}

// LLMMutation 表示LLM建议的变异操作
type LLMMutation struct {
	Operation string
	Position  int
	OldCall   string
	NewCall   string
}

// ShouldUseLLM 检查是否应该使用LLM API进行变异
func (fuzzer *Fuzzer) ShouldUseLLM() bool {
	if fuzzer.Config.LLMConfig == nil || !fuzzer.Config.LLMConfig.Enabled {
		return false
	}

	// 检查是否有新覆盖率（通过时间间隔判断）
	timeSinceLastCoverage := time.Since(fuzzer.Config.LLMConfig.lastNewCoverageTime)
	if timeSinceLastCoverage < time.Second*10 {
		// 如果在过去10秒内有新覆盖率，重置停滞计数器
		fuzzer.Config.LLMConfig.stallCounter = 0
		return false
	}

	// 更新停滞计数器
	fuzzer.Config.LLMConfig.stallCounter++

	// 定期输出当前状态以便追踪
	if fuzzer.Config.LLMConfig.stallCounter%100 == 0 {
		fuzzer.Logf(1, "LLM stall counter: %d/%d, time since last coverage: %v",
			fuzzer.Config.LLMConfig.stallCounter,
			fuzzer.Config.LLMConfig.StallThreshold,
			timeSinceLastCoverage)
	}

	// 如果停滞计数器超过阈值，根据使用频率决定是否使用LLM
	if fuzzer.Config.LLMConfig.stallCounter >= fuzzer.Config.LLMConfig.StallThreshold {
		// 使用频率是1-100的值，表示使用LLM的概率百分比
		useProb := fuzzer.Config.LLMConfig.UsageFrequency
		if useProb <= 0 {
			useProb = 10 // 默认值为10%
		}

		// 随机决定是否使用LLM
		rnd := fuzzer.rand()
		shouldUse := rnd.Intn(100) < useProb
		if shouldUse {
			fuzzer.Logf(1, "Coverage has stalled for %d iterations, trying LLM mutation",
				fuzzer.Config.LLMConfig.stallCounter)
			// 重置计数器，以便不会连续使用LLM
			fuzzer.Config.LLMConfig.stallCounter = 0
		}
		return shouldUse
	}

	return false
}

// UseLLMForMutation 使用LLM API对程序进行变异
func (fuzzer *Fuzzer) UseLLMForMutation(p *prog.Prog) (*prog.Prog, error) {
	if fuzzer.Config.LLMConfig == nil || fuzzer.Config.LLMConfig.APIURL == "" {
		return nil, fmt.Errorf("LLM API URL not configured")
	}

	// 将程序序列化为系统调用序列字符串
	callsStr := formatProgCalls(p)

	// 选择一个变异类型
	rnd := fuzzer.rand()
	mutationType := rnd.Intn(3)

	var instruction string
	var prompt string

	instruction = "你是一个系统安全专家，请根据以下系统调用序列，根据要求给出系统调用序列的变异操作"

	switch mutationType {
	case 0:
		// 添加系统调用
		pos := rnd.Intn(len(p.Calls) + 1)
		prompt = fmt.Sprintf("[INST] 系统调用序列：%s，请变异此序列以更容易触发内核漏洞。建议在位置%d添加什么系统调用？[/INST]", callsStr, pos)
	case 1:
		// 删除系统调用
		if len(p.Calls) <= 1 {
			// 如果程序只有一个调用，回退到添加操作
			pos := rnd.Intn(len(p.Calls) + 1)
			prompt = fmt.Sprintf("[INST] 系统调用序列：%s，请变异此序列以更容易触发内核漏洞。建议在位置%d添加什么系统调用？[/INST]", callsStr, pos)
		} else {
			prompt = fmt.Sprintf("[INST] 给定序列：%s，请删除最有可能暴露系统缺陷的调用：[/INST]", callsStr)
		}
	case 2:
		// 替换系统调用
		if len(p.Calls) == 0 {
			// 如果程序没有调用，回退到添加操作
			prompt = fmt.Sprintf("[INST] 系统调用序列：%s，请变异此序列以更容易触发内核漏洞。建议添加什么系统调用？[/INST]", callsStr)
		} else {
			pos := rnd.Intn(len(p.Calls))
			prompt = fmt.Sprintf("[INST] 以下调用序列可能触发异常行为，请替换位置%d的调用以增强漏洞触发能力：%s[/INST]", pos, callsStr)
		}
	}

	// 调用LLM API获取变异建议
	mutation, err := fuzzer.callLLMAPI(instruction, prompt)
	if err != nil {
		return nil, err
	}

	// 应用变异
	newProg, err := fuzzer.applyLLMMutation(p, mutation)
	if err != nil {
		fuzzer.Logf(1, "Failed to apply LLM mutation: %v", err)
		return p, nil // 返回原始程序
	}

	fuzzer.Logf(1, "Applied LLM mutation: %s", mutation.Operation)
	return newProg, nil
}

// callLLMAPI 调用LLM API获取变异建议
func (fuzzer *Fuzzer) callLLMAPI(instruction, input string) (*LLMMutation, error) {
	if fuzzer.Config.LLMConfig == nil || !fuzzer.Config.LLMConfig.Enabled {
		return nil, fmt.Errorf("LLM API not enabled")
	}

	// 确保API URL有效
	apiURL := fuzzer.Config.LLMConfig.APIURL
	if apiURL == "" {
		return nil, fmt.Errorf("LLM API URL not set")
	}

	var resp *http.Response
	var err error

	if fuzzer.Config.LLMConfig.UseOpenAIFormat {
		// 使用OpenAI标准格式
		type OpenAIMessage struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}

		type OpenAIRequest struct {
			Model     string          `json:"model"`
			Messages  []OpenAIMessage `json:"messages"`
			MaxTokens int             `json:"max_tokens"`
		}

		messages := []OpenAIMessage{
			{Role: "system", Content: instruction},
			{Role: "user", Content: input},
		}

		reqBody := OpenAIRequest{
			Model:     "gpt-3.5-turbo", // 默认模型
			Messages:  messages,
			MaxTokens: 100,
		}

		jsonBody, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal OpenAI request: %w", err)
		}

		fuzzer.Logf(3, "发送OpenAI格式请求到: %s", apiURL)
		resp, err = http.Post(apiURL+"/v1/chat/completions", "application/json", bytes.NewBuffer(jsonBody))
	} else {
		// 使用原来的格式
		reqBody := LLMRequest{
			Instruction: instruction,
			Input:       input,
		}

		jsonBody, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}

		fuzzer.Logf(3, "发送原格式请求到: %s", apiURL)
		resp, err = http.Post(apiURL, "application/json", bytes.NewBuffer(jsonBody))
	}

	if err != nil {
		return nil, fmt.Errorf("failed to send request to LLM API: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// 解析响应
	var output string
	if fuzzer.Config.LLMConfig.UseOpenAIFormat {
		// 解析OpenAI响应格式
		type OpenAIResponse struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		var openaiResp OpenAIResponse
		if err := json.Unmarshal(body, &openaiResp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal OpenAI response: %w, body: %s", err, string(body))
		}
		if len(openaiResp.Choices) == 0 {
			return nil, fmt.Errorf("no choices in OpenAI response: %s", string(body))
		}
		output = openaiResp.Choices[0].Message.Content
	} else {
		// 解析原来的响应格式
		var llmResp LLMResponse
		if err := json.Unmarshal(body, &llmResp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}
		output = llmResp.Output
	}

	// 解析LLM输出为变异操作
	return parseLLMOutput(output)
}

// formatProgCalls 将程序格式化为系统调用序列字符串
func formatProgCalls(p *prog.Prog) string {
	var callNames []string
	for _, call := range p.Calls {
		callNames = append(callNames, call.Meta.Name)
	}
	return fmt.Sprintf("[%s]", strings.Join(callNames, ", "))
}

// parseLLMOutput 解析LLM输出为变异操作
func parseLLMOutput(output string) (*LLMMutation, error) {
	// 查找尖括号中的内容
	startIdx := strings.Index(output, "<")
	endIdx := strings.Index(output, ">")

	if startIdx == -1 || endIdx == -1 || startIdx >= endIdx {
		return nil, fmt.Errorf("invalid LLM output format: %s", output)
	}

	// 提取操作内容
	opContent := output[startIdx+1 : endIdx]
	parts := strings.Split(opContent, " ")

	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid operation format: %s", opContent)
	}

	mutation := &LLMMutation{}

	// 解析操作类型
	opType := strings.ToUpper(parts[0])
	switch opType {
	case LLMOpAdd:
		// 格式: ADD pos='N' call='syscall_name'
		mutation.Operation = LLMOpAdd
		for i := 1; i < len(parts); i++ {
			if strings.HasPrefix(parts[i], "pos=") {
				posStr := strings.Trim(parts[i][4:], "'")
				pos, err := parsePosition(posStr)
				if err != nil {
					return nil, err
				}
				mutation.Position = pos
			} else if strings.HasPrefix(parts[i], "call=") {
				callName := strings.Trim(parts[i][5:], "'")
				mutation.NewCall = callName
			}
		}

	case LLMOpDelete:
		// 格式: DELETE pos='N' call='syscall_name'
		mutation.Operation = LLMOpDelete
		for i := 1; i < len(parts); i++ {
			if strings.HasPrefix(parts[i], "pos=") {
				posStr := strings.Trim(parts[i][4:], "'")
				pos, err := parsePosition(posStr)
				if err != nil {
					return nil, err
				}
				mutation.Position = pos
			} else if strings.HasPrefix(parts[i], "call=") {
				callName := strings.Trim(parts[i][5:], "'")
				mutation.OldCall = callName
			}
		}

	case LLMOpReplace:
		// 格式: REPLACE pos='N' old_call='syscall_name' new_call='syscall_name'
		mutation.Operation = LLMOpReplace
		for i := 1; i < len(parts); i++ {
			if strings.HasPrefix(parts[i], "pos=") {
				posStr := strings.Trim(parts[i][4:], "'")
				pos, err := parsePosition(posStr)
				if err != nil {
					return nil, err
				}
				mutation.Position = pos
			} else if strings.HasPrefix(parts[i], "old_call=") {
				callName := strings.Trim(parts[i][9:], "'")
				mutation.OldCall = callName
			} else if strings.HasPrefix(parts[i], "new_call=") {
				callName := strings.Trim(parts[i][9:], "'")
				mutation.NewCall = callName
			}
		}

	default:
		return nil, fmt.Errorf("unknown operation type: %s", opType)
	}

	return mutation, nil
}

// parsePosition 解析位置字符串为整数
func parsePosition(posStr string) (int, error) {
	pos := 0
	var err error

	if posStr == "" {
		return 0, nil
	}

	// 尝试解析为整数
	pos, err = strconv.Atoi(posStr)
	if err != nil {
		return 0, fmt.Errorf("invalid position: %s", posStr)
	}

	return pos, nil
}

// applyLLMMutation 应用LLM建议的变异到程序
func (fuzzer *Fuzzer) applyLLMMutation(p *prog.Prog, mutation *LLMMutation) (*prog.Prog, error) {
	if mutation == nil {
		return p, nil
	}

	// 创建程序的副本
	newProg := p.Clone()
	callCount := len(newProg.Calls)

	// 检查位置是否有效
	if mutation.Position < 0 || mutation.Position >= callCount {
		if mutation.Operation == LLMOpAdd && mutation.Position == callCount {
			// 允许在末尾添加
		} else {
			return nil, fmt.Errorf("invalid position: %d (call count: %d)", mutation.Position, callCount)
		}
	}

	switch mutation.Operation {
	case LLMOpAdd:
		// 找到对应的系统调用
		syscall := fuzzer.findSyscallByName(mutation.NewCall)
		if syscall == nil {
			return nil, fmt.Errorf("syscall not found: %s", mutation.NewCall)
		}

		// 创建新的系统调用
		call := prog.MakeCall(syscall, nil)
		if call == nil {
			return nil, fmt.Errorf("failed to create call: %s", mutation.NewCall)
		}

		// 插入系统调用
		if mutation.Position >= callCount {
			newProg.Calls = append(newProg.Calls, call)
		} else {
			newProg.Calls = append(newProg.Calls[:mutation.Position], append([]*prog.Call{call}, newProg.Calls[mutation.Position:]...)...)
		}

	case LLMOpDelete:
		// 删除系统调用
		if mutation.Position < callCount {
			newProg.RemoveCall(mutation.Position)
		}

	case LLMOpReplace:
		// 找到对应的系统调用
		syscall := fuzzer.findSyscallByName(mutation.NewCall)
		if syscall == nil {
			return nil, fmt.Errorf("syscall not found: %s", mutation.NewCall)
		}

		// 创建新的系统调用
		call := prog.MakeCall(syscall, nil)
		if call == nil {
			return nil, fmt.Errorf("failed to create call: %s", mutation.NewCall)
		}

		// 替换系统调用
		if mutation.Position < callCount {
			newProg.Calls[mutation.Position] = call
		}
	}

	// 检查程序是否有有效调用
	if len(newProg.Calls) == 0 {
		return nil, fmt.Errorf("no valid calls after mutation")
	}

	// 尝试序列化程序，确保它是有效的
	serialized := newProg.Serialize()
	if len(serialized) == 0 {
		return nil, fmt.Errorf("failed to serialize program after mutation")
	}

	return newProg, nil
}

// findSyscallByName 根据名称查找系统调用
func (fuzzer *Fuzzer) findSyscallByName(name string) *prog.Syscall {
	for _, call := range fuzzer.target.Syscalls {
		if strings.HasPrefix(call.Name, name) {
			return call
		}
	}
	return nil
}
