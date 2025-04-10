// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"crypto/sha1"
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
	if fuzzer.Config == nil {
		return nil, fmt.Errorf("fuzzer Config is nil")
	}

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

	// 记录完整配置以便调试
	fuzzer.Logf(1, "LLM API调用: URL=%s, UseOpenAIFormat=%v, StallThreshold=%d, UsageFrequency=%d",
		apiURL, fuzzer.Config.LLMConfig.UseOpenAIFormat,
		fuzzer.Config.LLMConfig.StallThreshold,
		fuzzer.Config.LLMConfig.UsageFrequency)

	// 保存一份配置副本，防止并发修改
	useOpenAIFormat := fuzzer.Config.LLMConfig.UseOpenAIFormat

	if useOpenAIFormat {
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

	// 确保配置在解析响应前仍然有效
	if fuzzer.Config == nil || fuzzer.Config.LLMConfig == nil {
		return nil, fmt.Errorf("LLM config became nil during API call")
	}

	// 记录原始响应以便调试
	fuzzer.Logf(3, "LLM API响应: %s", string(body))

	// 解析响应
	var output string
	if useOpenAIFormat {
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

		// 防止Choices[0].Message.Content为空
		if len(openaiResp.Choices) > 0 {
			output = openaiResp.Choices[0].Message.Content
			fuzzer.Logf(2, "解析的LLM输出: %s", output)
		} else {
			return nil, fmt.Errorf("empty choices in OpenAI response")
		}
	} else {
		// 解析原来的响应格式
		var llmResp LLMResponse
		if err := json.Unmarshal(body, &llmResp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}
		output = llmResp.Output
		fuzzer.Logf(2, "解析的LLM输出: %s", output)
	}

	if output == "" {
		return nil, fmt.Errorf("empty output from LLM API")
	}

	// 解析LLM输出为变异操作
	mutation, err := parseLLMOutput(output)
	if err != nil {
		fuzzer.Logf(1, "无法解析LLM输出为变异操作: %v", err)
		return nil, err
	}

	if mutation == nil {
		return nil, fmt.Errorf("parsed mutation is nil")
	}

	fuzzer.Logf(1, "成功解析变异操作: 类型=%s, 位置=%d", mutation.Operation, mutation.Position)
	return mutation, nil
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
	fmt.Printf("【LLM解析调试】开始解析输出: %s\n", output)

	if output == "" {
		fmt.Printf("【LLM解析调试】输出为空\n")
		return nil, fmt.Errorf("empty output to parse")
	}

	// 使用正则表达式匹配，这是最可靠的方法
	fmt.Printf("【LLM解析调试】尝试正则表达式匹配\n")

	// 尝试ADD匹配
	if match := addRegex.FindStringSubmatch(output); match != nil && len(match) >= 3 {
		fmt.Printf("【LLM解析调试】匹配到ADD模式: pos=%s, call=%s\n", match[1], match[2])
		pos, err := strconv.Atoi(match[1])
		if err != nil {
			fmt.Printf("【LLM解析调试】位置解析失败: %v\n", err)
			return nil, fmt.Errorf("invalid position in ADD operation: %s", match[1])
		}
		return &LLMMutation{
			Operation: LLMOpAdd,
			Position:  pos,
			NewCall:   match[2],
		}, nil
	}

	// 尝试DELETE匹配
	if match := deleteRegex.FindStringSubmatch(output); match != nil && len(match) >= 3 {
		fmt.Printf("【LLM解析调试】匹配到DELETE模式: pos=%s, call=%s\n", match[1], match[2])
		pos, err := strconv.Atoi(match[1])
		if err != nil {
			fmt.Printf("【LLM解析调试】位置解析失败: %v\n", err)
			return nil, fmt.Errorf("invalid position in DELETE operation: %s", match[1])
		}
		return &LLMMutation{
			Operation: LLMOpDelete,
			Position:  pos,
			OldCall:   match[2],
		}, nil
	}

	// 尝试REPLACE匹配
	if match := replaceRegex.FindStringSubmatch(output); match != nil && len(match) >= 4 {
		fmt.Printf("【LLM解析调试】匹配到REPLACE模式: pos=%s, old_call=%s, new_call=%s\n",
			match[1], match[2], match[3])
		pos, err := strconv.Atoi(match[1])
		if err != nil {
			fmt.Printf("【LLM解析调试】位置解析失败: %v\n", err)
			return nil, fmt.Errorf("invalid position in REPLACE operation: %s", match[1])
		}
		return &LLMMutation{
			Operation: LLMOpReplace,
			Position:  pos,
			OldCall:   match[2],
			NewCall:   match[3],
		}, nil
	}

	fmt.Printf("【LLM解析调试】正则表达式匹配失败，尝试尖括号格式解析\n")

	// 尝试使用尖括号格式解析
	startIdx := strings.Index(output, "<")
	endIdx := strings.Index(output, ">")

	if startIdx != -1 && endIdx != -1 && startIdx < endIdx {
		fmt.Printf("【LLM解析调试】找到尖括号内容: %s\n", output[startIdx:endIdx+1])

		// 提取操作内容
		opContent := output[startIdx+1 : endIdx]
		fmt.Printf("【LLM解析调试】提取的操作内容: %s\n", opContent)

		parts := strings.Split(opContent, " ")
		fmt.Printf("【LLM解析调试】分割后的部分: %v\n", parts)

		if len(parts) < 2 {
			fmt.Printf("【LLM解析调试】部分数量不足: %d\n", len(parts))
			return nil, fmt.Errorf("invalid operation format: %s", opContent)
		}

		mutation := &LLMMutation{}

		// 解析操作类型
		opType := strings.ToUpper(parts[0])
		fmt.Printf("【LLM解析调试】操作类型: %s\n", opType)

		switch opType {
		case LLMOpAdd:
			// 格式: ADD pos='N' call='syscall_name'
			fmt.Printf("【LLM解析调试】识别ADD操作\n")
			mutation.Operation = LLMOpAdd
			for i := 1; i < len(parts); i++ {
				fmt.Printf("【LLM解析调试】解析参数: %s\n", parts[i])
				if strings.HasPrefix(parts[i], "pos=") {
					posStr := strings.Trim(parts[i][4:], "'")
					fmt.Printf("【LLM解析调试】提取位置: %s\n", posStr)
					pos, err := parsePosition(posStr)
					if err != nil {
						fmt.Printf("【LLM解析调试】位置解析失败: %v\n", err)
						return nil, err
					}
					mutation.Position = pos
				} else if strings.HasPrefix(parts[i], "call=") {
					callName := strings.Trim(parts[i][5:], "'")
					fmt.Printf("【LLM解析调试】提取调用名称: %s\n", callName)
					mutation.NewCall = callName
				}
			}

		case LLMOpDelete:
			// 格式: DELETE pos='N' call='syscall_name'
			fmt.Printf("【LLM解析调试】识别DELETE操作\n")
			mutation.Operation = LLMOpDelete
			for i := 1; i < len(parts); i++ {
				fmt.Printf("【LLM解析调试】解析参数: %s\n", parts[i])
				if strings.HasPrefix(parts[i], "pos=") {
					posStr := strings.Trim(parts[i][4:], "'")
					fmt.Printf("【LLM解析调试】提取位置: %s\n", posStr)
					pos, err := parsePosition(posStr)
					if err != nil {
						fmt.Printf("【LLM解析调试】位置解析失败: %v\n", err)
						return nil, err
					}
					mutation.Position = pos
				} else if strings.HasPrefix(parts[i], "call=") {
					callName := strings.Trim(parts[i][5:], "'")
					fmt.Printf("【LLM解析调试】提取调用名称: %s\n", callName)
					mutation.OldCall = callName
				}
			}

		case LLMOpReplace:
			// 格式: REPLACE pos='N' old_call='syscall_name' new_call='syscall_name'
			fmt.Printf("【LLM解析调试】识别REPLACE操作\n")
			mutation.Operation = LLMOpReplace
			for i := 1; i < len(parts); i++ {
				fmt.Printf("【LLM解析调试】解析参数: %s\n", parts[i])
				if strings.HasPrefix(parts[i], "pos=") {
					posStr := strings.Trim(parts[i][4:], "'")
					fmt.Printf("【LLM解析调试】提取位置: %s\n", posStr)
					pos, err := parsePosition(posStr)
					if err != nil {
						fmt.Printf("【LLM解析调试】位置解析失败: %v\n", err)
						return nil, err
					}
					mutation.Position = pos
				} else if strings.HasPrefix(parts[i], "old_call=") {
					callName := strings.Trim(parts[i][9:], "'")
					fmt.Printf("【LLM解析调试】提取旧调用名称: %s\n", callName)
					mutation.OldCall = callName
				} else if strings.HasPrefix(parts[i], "new_call=") {
					callName := strings.Trim(parts[i][9:], "'")
					fmt.Printf("【LLM解析调试】提取新调用名称: %s\n", callName)
					mutation.NewCall = callName
				}
			}

		default:
			fmt.Printf("【LLM解析调试】未知操作类型: %s\n", opType)
			return nil, fmt.Errorf("unknown operation type: %s", opType)
		}

		// 验证操作的完整性
		fmt.Printf("【LLM解析调试】验证操作完整性: Operation=%s, Position=%d, OldCall=%s, NewCall=%s\n",
			mutation.Operation, mutation.Position, mutation.OldCall, mutation.NewCall)

		if mutation.Operation == LLMOpAdd && mutation.NewCall == "" {
			fmt.Printf("【LLM解析调试】ADD操作缺少调用名称\n")
			return nil, fmt.Errorf("ADD operation missing call name")
		} else if mutation.Operation == LLMOpDelete && mutation.Position < 0 {
			fmt.Printf("【LLM解析调试】DELETE操作缺少有效位置\n")
			return nil, fmt.Errorf("DELETE operation missing valid position")
		} else if mutation.Operation == LLMOpReplace && (mutation.NewCall == "" || mutation.Position < 0) {
			fmt.Printf("【LLM解析调试】REPLACE操作缺少必要字段\n")
			return nil, fmt.Errorf("REPLACE operation missing required fields")
		}

		fmt.Printf("【LLM解析调试】尖括号格式解析成功\n")
		return mutation, nil
	}

	// 如果上述方法都失败，尝试直接从文本中提取关键信息
	fmt.Printf("【LLM解析调试】尖括号格式解析失败，尝试从文本提取关键信息\n")

	lowOutput := strings.ToLower(output)

	// 尝试识别ADD操作
	if strings.Contains(lowOutput, "add") && (strings.Contains(lowOutput, "position") || strings.Contains(lowOutput, "pos")) {
		fmt.Printf("【LLM解析调试】文本中可能包含ADD操作\n")

		// 尝试找出位置
		posMatch := regexp.MustCompile(`(?:position|pos)(?:ition)?[:\s=]*(\d+)`).FindStringSubmatch(lowOutput)
		var pos int
		if posMatch != nil && len(posMatch) > 1 {
			fmt.Printf("【LLM解析调试】找到位置匹配: %s\n", posMatch[1])
			pos, _ = strconv.Atoi(posMatch[1])
		} else {
			fmt.Printf("【LLM解析调试】未找到位置\n")
		}

		// 尝试找出调用名称
		callMatch := regexp.MustCompile(`(?:call|syscall|system call)[:\s=]*['"]?([a-zA-Z0-9_$]+)['"]?`).FindStringSubmatch(lowOutput)
		if callMatch != nil && len(callMatch) > 1 {
			fmt.Printf("【LLM解析调试】找到调用名称匹配: %s\n", callMatch[1])
			return &LLMMutation{
				Operation: LLMOpAdd,
				Position:  pos,
				NewCall:   callMatch[1],
			}, nil
		} else {
			fmt.Printf("【LLM解析调试】未找到调用名称\n")
		}
	}

	// 尝试识别DELETE操作
	if strings.Contains(lowOutput, "delete") || strings.Contains(lowOutput, "remove") {
		fmt.Printf("【LLM解析调试】文本中可能包含DELETE操作\n")

		posMatch := regexp.MustCompile(`(?:position|pos)(?:ition)?[:\s=]*(\d+)`).FindStringSubmatch(lowOutput)
		var pos int
		if posMatch != nil && len(posMatch) > 1 {
			fmt.Printf("【LLM解析调试】找到位置匹配: %s\n", posMatch[1])
			pos, _ = strconv.Atoi(posMatch[1])
		} else {
			fmt.Printf("【LLM解析调试】未找到位置\n")
		}

		// 尝试找出调用名称
		callMatch := regexp.MustCompile(`(?:call|syscall|system call)[:\s=]*['"]?([a-zA-Z0-9_$]+)['"]?`).FindStringSubmatch(lowOutput)
		if callMatch != nil && len(callMatch) > 1 {
			fmt.Printf("【LLM解析调试】找到调用名称匹配: %s\n", callMatch[1])
			return &LLMMutation{
				Operation: LLMOpDelete,
				Position:  pos,
				OldCall:   callMatch[1],
			}, nil
		} else {
			fmt.Printf("【LLM解析调试】未找到调用名称\n")
		}
	}

	// 尝试识别REPLACE操作
	if strings.Contains(lowOutput, "replace") || strings.Contains(lowOutput, "change") {
		fmt.Printf("【LLM解析调试】文本中可能包含REPLACE操作\n")

		posMatch := regexp.MustCompile(`(?:position|pos)(?:ition)?[:\s=]*(\d+)`).FindStringSubmatch(lowOutput)
		var pos int
		if posMatch != nil && len(posMatch) > 1 {
			fmt.Printf("【LLM解析调试】找到位置匹配: %s\n", posMatch[1])
			pos, _ = strconv.Atoi(posMatch[1])
		} else {
			fmt.Printf("【LLM解析调试】未找到位置\n")
		}

		// 尝试找出旧调用名称
		oldCallMatch := regexp.MustCompile(`(?:old|original|replace)(?:_call)?[:\s=]*['"]?([a-zA-Z0-9_$]+)['"]?`).FindStringSubmatch(lowOutput)
		var oldCall string
		if oldCallMatch != nil && len(oldCallMatch) > 1 {
			fmt.Printf("【LLM解析调试】找到旧调用名称匹配: %s\n", oldCallMatch[1])
			oldCall = oldCallMatch[1]
		} else {
			fmt.Printf("【LLM解析调试】未找到旧调用名称\n")
		}

		// 尝试找出新调用名称
		newCallMatch := regexp.MustCompile(`(?:new|with|to)(?:_call)?[:\s=]*['"]?([a-zA-Z0-9_$]+)['"]?`).FindStringSubmatch(lowOutput)
		if newCallMatch != nil && len(newCallMatch) > 1 {
			fmt.Printf("【LLM解析调试】找到新调用名称匹配: %s\n", newCallMatch[1])
			return &LLMMutation{
				Operation: LLMOpReplace,
				Position:  pos,
				OldCall:   oldCall,
				NewCall:   newCallMatch[1],
			}, nil
		} else {
			fmt.Printf("【LLM解析调试】未找到新调用名称\n")
		}
	}

	fmt.Printf("【LLM解析调试】所有解析方法都失败\n")
	return nil, fmt.Errorf("无法解析LLM输出: %s", output)
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

	fuzzer.Logf(0, "【调试】尝试应用变异: 操作=%s, 位置=%d, 旧调用=%s, 新调用=%s",
		mutation.Operation, mutation.Position, mutation.OldCall, mutation.NewCall)

	// 创建程序的副本
	newProg := p.Clone()
	callCount := len(newProg.Calls)

	// 检查位置是否有效
	if mutation.Position < 0 || mutation.Position >= callCount {
		if mutation.Operation == LLMOpAdd && mutation.Position == callCount {
			// 允许在末尾添加
		} else {
			return nil, fmt.Errorf("无效的位置: %d (调用数量: %d)", mutation.Position, callCount)
		}
	}

	originalCallName := ""
	if mutation.Position < callCount {
		originalCallName = newProg.Calls[mutation.Position].Meta.Name
	}

	switch mutation.Operation {
	case LLMOpAdd:
		// 找到对应的系统调用
		syscall := fuzzer.findSyscallByName(mutation.NewCall)
		if syscall == nil {
			fuzzer.Logf(0, "【调试】找不到系统调用: %s", mutation.NewCall)
			return nil, fmt.Errorf("找不到系统调用: %s", mutation.NewCall)
		}

		fuzzer.Logf(0, "【调试】成功找到系统调用: %s", syscall.Name)

		// 创建新的系统调用
		call := prog.MakeCall(syscall, nil)
		if call == nil {
			return nil, fmt.Errorf("无法创建调用: %s", mutation.NewCall)
		}

		// 插入系统调用
		if mutation.Position >= callCount {
			newProg.Calls = append(newProg.Calls, call)
			fuzzer.Logf(0, "【调试】已将调用 %s 添加到末尾", syscall.Name)
		} else {
			newProg.Calls = append(newProg.Calls[:mutation.Position], append([]*prog.Call{call}, newProg.Calls[mutation.Position:]...)...)
			fuzzer.Logf(0, "【调试】已将调用 %s 插入到位置 %d", syscall.Name, mutation.Position)
		}

	case LLMOpDelete:
		// 删除系统调用
		if mutation.Position < callCount {
			fuzzer.Logf(0, "【调试】即将删除位置 %d 的调用: %s", mutation.Position, originalCallName)
			newProg.RemoveCall(mutation.Position)
		}

	case LLMOpReplace:
		// 找到对应的系统调用
		syscall := fuzzer.findSyscallByName(mutation.NewCall)
		if syscall == nil {
			fuzzer.Logf(0, "【调试】找不到系统调用: %s", mutation.NewCall)
			return nil, fmt.Errorf("找不到系统调用: %s", mutation.NewCall)
		}

		fuzzer.Logf(0, "【调试】成功找到系统调用: %s，将替换位置 %d 的调用 %s",
			syscall.Name, mutation.Position, originalCallName)

		// 创建新的系统调用
		call := prog.MakeCall(syscall, nil)
		if call == nil {
			return nil, fmt.Errorf("无法创建调用: %s", mutation.NewCall)
		}

		// 替换系统调用
		if mutation.Position < callCount {
			newProg.Calls[mutation.Position] = call
		}
	}

	// 检查程序是否有有效调用
	if len(newProg.Calls) == 0 {
		return nil, fmt.Errorf("变异后无有效调用")
	}

	// 尝试序列化程序，确保它是有效的
	serialized := newProg.Serialize()
	if len(serialized) == 0 {
		return nil, fmt.Errorf("变异后程序无法序列化")
	}

	// 校验序列化后的程序是否与原始程序不同
	originalHash := fmt.Sprintf("%x", sha1.Sum(p.Serialize()))
	newHash := fmt.Sprintf("%x", sha1.Sum(serialized))

	if originalHash == newHash {
		fuzzer.Logf(0, "【调试】警告：变异后程序的哈希值与原始程序相同: %s", newHash)
	} else {
		fuzzer.Logf(0, "【调试】变异成功，程序哈希值已改变: %s -> %s", originalHash, newHash)
	}

	return newProg, nil
}

// findSyscallByName 根据名称查找系统调用
func (fuzzer *Fuzzer) findSyscallByName(name string) *prog.Syscall {
	// 先尝试精确匹配
	for _, call := range fuzzer.target.Syscalls {
		if call.Name == name {
			return call
		}
	}

	// 如果精确匹配失败，尝试前缀匹配
	for _, call := range fuzzer.target.Syscalls {
		if strings.HasPrefix(call.Name, name) {
			return call
		}
	}

	// 如果前缀匹配失败，尝试包含匹配
	for _, call := range fuzzer.target.Syscalls {
		if strings.Contains(call.Name, name) {
			return call
		}
	}

	// 处理一些特殊情况
	if name == "clone" {
		// 尝试查找相关的克隆调用
		for _, call := range fuzzer.target.Syscalls {
			if strings.Contains(call.Name, "clone") {
				return call
			}
		}
	} else if name == "mount" || strings.HasPrefix(name, "mount$") {
		// 尝试查找任何挂载相关调用
		for _, call := range fuzzer.target.Syscalls {
			if strings.Contains(call.Name, "mount") {
				return call
			}
		}
	} else if strings.Contains(name, "$") {
		// 处理带有$分隔符的调用，尝试匹配主调用名
		mainName := strings.Split(name, "$")[0]
		for _, call := range fuzzer.target.Syscalls {
			if strings.HasPrefix(call.Name, mainName) {
				return call
			}
		}
	}

	// 记录未找到的系统调用名称以便调试
	fuzzer.Logf(0, "【调试】未能找到系统调用: %s", name)

	return nil
}
