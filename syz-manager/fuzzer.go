// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"math/rand"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

// 启动LLM增强循环
func (mgr *Manager) startLLMEnhanceLoop(ctx context.Context) {
	if mgr.cfg.Experimental.LLMAPIEnabled {
		go mgr.llmEnhanceLoop(ctx)
		log.Logf(0, "已启动LLM增强循环")
	}
}

// LLM增强循环，定期从高覆盖率程序中选择样本进行增强
func (mgr *Manager) llmEnhanceLoop(ctx context.Context) {
	// 初始延迟5分钟，等待系统稳定
	time.Sleep(5 * time.Minute)

	// 每10分钟尝试增强一次
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mgr.tryEnhanceWithLLM()
		case <-ctx.Done():
			return
		}
	}
}

// 尝试使用LLM增强程序
func (mgr *Manager) tryEnhanceWithLLM() {
	fuzzerObj := mgr.fuzzer.Load()
	if fuzzerObj == nil {
		log.Logf(1, "无法进行LLM增强: fuzzer对象为空")
		return
	}

	// 检查API是否空闲
	if fuzzerObj.Config.LLMConfig == nil {
		return
	}

	// 我们使用一个简单的策略:
	// 随机决定是否使用LLM增强程序，使用LLM配置中的UsageFrequency作为概率参考
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	freq := fuzzerObj.Config.LLMConfig.UsageFrequency
	if freq <= 0 {
		freq = 10 // 默认10%的概率
	}

	if rnd.Intn(100) >= freq {
		log.Logf(3, "随机跳过LLM增强 (频率: %d%%)", freq)
		return
	}

	log.Logf(1, "开始LLM增强...")
	// 使用Manager中的LLMEnhancer来实现增强功能
	if enhancer := mgr.llmEnhancer; enhancer != nil {
		enhancer.enhanceWithLLM()
	} else {
		log.Logf(1, "LLM增强器未初始化")
	}
}
