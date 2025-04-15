// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"os"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	// 添加最大尝试次数
	maxTries := ncalls * 10 // 为每个调用留出足够的尝试次数
	tries := 0
	for len(p.Calls) < ncalls {
		tries++
		if tries > maxTries {
			// 如果尝试次数过多，打印警告并退出循环
			fmt.Fprintf(os.Stderr, "警告：无法生成足够的系统调用，已尝试%d次\n", tries)
			break
		}
		calls := r.generateCall(s, p, len(p.Calls))
		// 检查generateCall是否返回nil
		if calls == nil {
			// 无法生成调用，但我们可以继续尝试
			continue
		}
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	// 添加空调用检查
	if len(p.Calls) > 0 {
		p.sanitizeFix()
	}
	p.debugValidate()
	return p
}
