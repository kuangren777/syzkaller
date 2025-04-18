// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"slices"
	"sort"
)

// Calulation of call-to-call priorities.
// For a given pair of calls X and Y, the priority is our guess as to whether
// additional of call Y into a program containing call X is likely to give
// new coverage or not.
// The current algorithm has two components: static and dynamic.
// The static component is based on analysis of argument types. For example,
// if call X and call Y both accept fd[sock], then they are more likely to give
// new coverage together.
// The dynamic component is based on frequency of occurrence of a particular
// pair of syscalls in a single program in corpus. For example, if socket and
// connect frequently occur in programs together, we give higher priority to
// this pair of syscalls.
// Note: the current implementation is very basic, there is no theory behind any
// constants.

func (target *Target) CalculatePriorities(corpus []*Prog) [][]int32 {
	static := target.calcStaticPriorities()
	if len(corpus) != 0 {
		// Let's just sum the static and dynamic distributions.
		dynamic := target.calcDynamicPrio(corpus)
		for i, prios := range dynamic {
			dst := static[i]
			for j, p := range prios {
				dst[j] += p
			}
		}
	}
	return static
}

func (target *Target) calcStaticPriorities() [][]int32 {
	uses := target.calcResourceUsage()
	prios := make([][]int32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]int32, len(target.Syscalls))
	}
	for _, weights := range uses {
		for _, w0 := range weights {
			for _, w1 := range weights {
				if w0.call == w1.call {
					// Self-priority is assigned below.
					continue
				}
				// The static priority is assigned based on the direction of arguments. A higher priority will be
				// assigned when c0 is a call that produces a resource and c1 a call that uses that resource.
				prios[w0.call][w1.call] += w0.inout*w1.in*3/2 + w0.inout*w1.inout
			}
		}
	}
	// The value assigned for self-priority (call wrt itself) have to be high, but not too high.
	for c0, pp := range prios {
		max := slices.Max(pp)
		if max == 0 {
			pp[c0] = 1
		} else {
			pp[c0] = max * 3 / 4
		}
	}
	normalizePrios(prios)
	return prios
}

func (target *Target) calcResourceUsage() map[string]map[int]weights {
	uses := make(map[string]map[int]weights)
	ForeachType(target.Syscalls, func(t Type, ctx *TypeCtx) {
		c := ctx.Meta
		switch a := t.(type) {
		case *ResourceType:
			if target.AuxResources[a.Desc.Name] {
				noteUsagef(uses, c, 1, ctx.Dir, "res%v", a.Desc.Name)
			} else {
				str := "res"
				for i, k := range a.Desc.Kind {
					str += "-" + k
					w := int32(10)
					if i < len(a.Desc.Kind)-1 {
						w = 2
					}
					noteUsage(uses, c, w, ctx.Dir, str)
				}
			}
		case *PtrType:
			if _, ok := a.Elem.(*StructType); ok {
				noteUsagef(uses, c, 10, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if _, ok := a.Elem.(*UnionType); ok {
				noteUsagef(uses, c, 10, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if arr, ok := a.Elem.(*ArrayType); ok {
				noteUsagef(uses, c, 10, ctx.Dir, "ptrto-%v", arr.Elem.Name())
			}
		case *BufferType:
			switch a.Kind {
			case BufferBlobRand, BufferBlobRange, BufferText, BufferCompressed:
			case BufferString, BufferGlob:
				if a.SubKind != "" {
					noteUsagef(uses, c, 2, ctx.Dir, "str-%v", a.SubKind)
				}
			case BufferFilename:
				noteUsage(uses, c, 10, DirIn, "filename")
			default:
				panic("unknown buffer kind")
			}
		case *VmaType:
			noteUsage(uses, c, 5, ctx.Dir, "vma")
		case *IntType:
			switch a.Kind {
			case IntPlain, IntRange:
			default:
				panic("unknown int kind")
			}
		}
	})
	return uses
}

type weights struct {
	call  int
	in    int32
	inout int32
}

func noteUsage(uses map[string]map[int]weights, c *Syscall, weight int32, dir Dir, str string) {
	noteUsagef(uses, c, weight, dir, "%v", str)
}

func noteUsagef(uses map[string]map[int]weights, c *Syscall, weight int32, dir Dir, str string, args ...interface{}) {
	id := fmt.Sprintf(str, args...)
	if uses[id] == nil {
		uses[id] = make(map[int]weights)
	}
	callWeight := uses[id][c.ID]
	callWeight.call = c.ID
	if dir != DirOut {
		if weight > uses[id][c.ID].in {
			callWeight.in = weight
		}
	}
	if weight > uses[id][c.ID].inout {
		callWeight.inout = weight
	}
	uses[id][c.ID] = callWeight
}

func (target *Target) calcDynamicPrio(corpus []*Prog) [][]int32 {
	prios := make([][]int32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]int32, len(target.Syscalls))
	}
	for _, p := range corpus {
		for idx0, c0 := range p.Calls {
			for _, c1 := range p.Calls[idx0+1:] {
				prios[c0.Meta.ID][c1.Meta.ID]++
			}
		}
	}
	for i := range prios {
		for j, val := range prios[i] {
			// It's more important that some calls do coexist than whether
			// it happened 50 or 100 times.
			// Let's use sqrt() to lessen the effect of large counts.
			prios[i][j] = int32(2.0 * math.Sqrt(float64(val)))
		}
	}
	normalizePrios(prios)
	return prios
}

// normalizePrio distributes |N| * 10 points proportional to the values in the matrix.
func normalizePrios(prios [][]int32) {
	total := 10 * int32(len(prios))
	for _, prio := range prios {
		sum := int32(0)
		for _, p := range prio {
			sum += p
		}
		if sum == 0 {
			continue
		}
		for i, p := range prio {
			prio[i] = p * total / sum
		}
	}
}

// ChooseTable allows to do a weighted choice of a syscall for a given syscall
// based on call-to-call priorities and a set of enabled and generatable syscalls.
type ChoiceTable struct {
	target *Target
	runs   [][]int32
	calls  []*Syscall
}

func (target *Target) BuildChoiceTable(corpus []*Prog, enabled map[*Syscall]bool) *ChoiceTable {
	if enabled == nil {
		enabled = make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			enabled[c] = true
		}
	}
	noGenerateCalls := make(map[int]bool)
	enabledCalls := make(map[*Syscall]bool)
	for call := range enabled {
		if call.Attrs.NoGenerate {
			noGenerateCalls[call.ID] = true
		} else if !call.Attrs.Disabled {
			enabledCalls[call] = true
		}
	}
	var generatableCalls []*Syscall
	for c := range enabledCalls {
		generatableCalls = append(generatableCalls, c)
	}
	if len(generatableCalls) == 0 {
		// 如果没有可生成的调用，打印警告并构建一个基本的ChoiceTable
		fmt.Fprintf(os.Stderr, "警告：没有启用和可生成的系统调用，将使用默认值\n")
		// 返回一个空的但有效的ChoiceTable，避免后续nil指针错误
		return &ChoiceTable{target, nil, nil}
	}
	sort.Slice(generatableCalls, func(i, j int) bool {
		return generatableCalls[i].ID < generatableCalls[j].ID
	})
	validPrograms := make([]*Prog, 0, len(corpus))
	for _, p := range corpus {
		hasDisabledCall := false
		for _, call := range p.Calls {
			if !enabledCalls[call.Meta] && !noGenerateCalls[call.Meta.ID] {
				fmt.Printf("corpus contains disabled syscall %v\n", call.Meta.Name)
				fmt.Printf("warning: disabled syscall found in corpus, skipping this program\n")
				hasDisabledCall = true
				break
			}
		}
		if !hasDisabledCall {
			validPrograms = append(validPrograms, p)
		}
	}

	// 使用过滤后的有效程序集合进行后续操作
	prios := target.CalculatePriorities(validPrograms)
	run := make([][]int32, len(target.Syscalls))
	// ChoiceTable.runs[][] contains cumulated sum of weighted priority numbers.
	// This helps in quick binary search with biases when generating programs.
	// This only applies for system calls that are enabled for the target.
	for i := range run {
		if !enabledCalls[target.Syscalls[i]] {
			continue
		}
		run[i] = make([]int32, len(target.Syscalls))
		var sum int32
		for j := range run[i] {
			if enabledCalls[target.Syscalls[j]] {
				sum += prios[i][j]
			}
			run[i][j] = sum
		}
	}
	return &ChoiceTable{target, run, generatableCalls}
}

func (ct *ChoiceTable) Generatable(call int) bool {
	return ct.runs[call] != nil
}

func (ct *ChoiceTable) choose(r *rand.Rand, bias int) int {
	// 首先检查是否有任何可生成的系统调用
	var generatableCalls []int
	for i := range ct.calls {
		if ct.Generatable(i) {
			generatableCalls = append(generatableCalls, i)
		}
	}

	// 如果没有可生成的调用，记录错误并返回-1（调用者应当处理这种情况）
	if len(generatableCalls) == 0 {
		fmt.Fprintf(os.Stderr, "警告：没有可生成的系统调用\n")
		return -1
	}

	if r.Intn(100) < 5 {
		// Let's make 5% decisions totally at random.
		// 确保选择的是可生成的调用
		return generatableCalls[r.Intn(len(generatableCalls))]
	}

	// 如果bias无效或不可生成，选择一个随机但有效的调用
	if bias < 0 || !ct.Generatable(bias) {
		if bias >= 0 {
			fmt.Fprintf(os.Stderr, "警告：偏向不可生成的系统调用 %v，将选择其他调用\n",
				ct.target.Syscalls[bias].Name)
		}
		return generatableCalls[r.Intn(len(generatableCalls))]
	}

	run := ct.runs[bias]
	runSum := int(run[len(run)-1])
	// 确保runSum不为0
	if runSum == 0 {
		fmt.Fprintf(os.Stderr, "警告：选择偏向的系统调用时runSum为0，将选择其他随机调用\n")
		return generatableCalls[r.Intn(len(generatableCalls))]
	}
	x := int32(r.Intn(runSum) + 1)
	// 确保run的长度不为0
	if len(run) == 0 {
		fmt.Fprintf(os.Stderr, "警告：run长度为0，将选择其他随机调用\n")
		return generatableCalls[r.Intn(len(generatableCalls))]
	}
	res := sort.Search(len(run), func(i int) bool {
		return run[i] >= x
	})

	// 如果选择了不可生成的调用，则回退到随机选择一个有效调用
	if !ct.Generatable(res) {
		fmt.Fprintf(os.Stderr, "警告：选择了不可生成的系统调用 %v，将选择其他调用\n",
			ct.target.Syscalls[res].Name)
		return generatableCalls[r.Intn(len(generatableCalls))]
	}

	return res
}
