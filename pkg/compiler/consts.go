// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type ConstInfo struct {
	Consts   []*Const
	Includes []string
	Incdirs  []string
	Defines  map[string]string
}

type Const struct {
	Name string
	Pos  ast.Pos
	Used bool // otherwise only defined
}

func ExtractConsts(desc *ast.Description, target *targets.Target, eh ast.ErrorHandler) map[string]*ConstInfo {
	res := Compile(desc, nil, target, eh)
	if res == nil {
		return nil
	}
	return res.fileConsts
}

// FabricateSyscallConsts adds syscall number constants to consts map.
// Used for test OS to not bother specifying consts for all syscalls.
func FabricateSyscallConsts(target *targets.Target, constInfo map[string]*ConstInfo, cf *ConstFile) {
	if !target.SyscallNumbers {
		return
	}
	for _, info := range constInfo {
		for _, c := range info.Consts {
			if strings.HasPrefix(c.Name, target.SyscallPrefix) {
				cf.addConst(target.Arch, c.Name, 0, true, false)
			}
		}
	}
}

type constContext struct {
	infos           map[string]*constInfo
	instantionStack []map[string]ast.Pos
}

// extractConsts returns list of literal constants and other info required for const value extraction.
func (comp *compiler) extractConsts() map[string]*ConstInfo {
	ctx := &constContext{
		infos: make(map[string]*constInfo),
	}
	extractIntConsts := ast.Recursive(func(n0 ast.Node) bool {
		if n, ok := n0.(*ast.Int); ok {
			comp.addConst(ctx, n.Pos, n.Ident)
		}
		return true
	})
	comp.desc.Walk(extractIntConsts)
	for _, decl := range comp.desc.Nodes {
		pos, _, _ := decl.Info()
		info := ctx.getConstInfo(pos)
		switch n := decl.(type) {
		case *ast.Include:
			info.includeArray = append(info.includeArray, n.File.Value)
		case *ast.Incdir:
			info.incdirArray = append(info.incdirArray, n.Dir.Value)
		case *ast.Define:
			v := fmt.Sprint(n.Value.Value)
			switch {
			case n.Value.CExpr != "":
				v = n.Value.CExpr
			case n.Value.Ident != "":
				v = n.Value.Ident
			}
			name := n.Name.Name
			if _, builtin := comp.builtinConsts[name]; builtin {
				comp.error(pos, "redefining builtin const %v", name)
			}
			info.defines[name] = v
			ctx.addConst(pos, name, false)
		case *ast.Call:
			if comp.target.HasCallNumber(n.CallName) {
				comp.addConst(ctx, pos, comp.target.SyscallPrefix+n.CallName)
			}
			for _, attr := range n.Attrs {
				if callAttrs[attr.Ident].Type == intAttr {
					comp.addConst(ctx, attr.Pos, attr.Args[0].Ident)
				}
			}
		case *ast.Struct:
			// The instantionStack allows to add consts that are used in template structs
			// to all files that use the template. Without this we would add these consts
			// to only one random file, which would leads to flaky changes in const files.
			ctx.instantionStack = append(ctx.instantionStack, comp.structFiles[n])
			for _, attr := range n.Attrs {
				attrDesc := structOrUnionAttrs(n)[attr.Ident]
				if attrDesc.Type == intAttr {
					comp.addConst(ctx, attr.Pos, attr.Args[0].Ident)
				}
			}
			foreachFieldAttrConst(n, func(t *ast.Type) {
				comp.addConst(ctx, t.Pos, t.Ident)
			})
			extractIntConsts(n)
			comp.extractTypeConsts(ctx, decl)
			ctx.instantionStack = ctx.instantionStack[:len(ctx.instantionStack)-1]
		}
		switch decl.(type) {
		case *ast.Call, *ast.Resource, *ast.TypeDef:
			comp.extractTypeConsts(ctx, decl)
		}
	}
	return convertConstInfo(ctx, comp.fileMetas)
}

func foreachFieldAttrConst(n *ast.Struct, cb func(*ast.Type)) {
	for _, field := range n.Fields {
		for _, attr := range field.Attrs {
			attrDesc := structOrUnionFieldAttrs(n)[attr.Ident]
			if attrDesc == nil {
				return
			}
			if attrDesc.Type != exprAttr {
				// For now, only these field attrs may have consts.
				return
			}
			ast.Recursive(func(n ast.Node) bool {
				t, ok := n.(*ast.Type)
				if !ok || t.Expression != nil {
					return true
				}
				if t.Ident != valueIdent {
					cb(t)
				}
				return false
			})(attr.Args[0])
		}
	}
}

func (comp *compiler) extractTypeConsts(ctx *constContext, n ast.Node) {
	comp.foreachType(n, func(t *ast.Type, desc *typeDesc, args []*ast.Type, _ prog.IntTypeCommon) {
		for i, arg := range args {
			if desc.Args[i].Type.Kind&kindInt != 0 {
				if arg.Ident != "" {
					comp.addConst(ctx, arg.Pos, arg.Ident)
				}
				for _, col := range arg.Colon {
					if col.Ident != "" {
						comp.addConst(ctx, col.Pos, col.Ident)
					}
				}
			}
		}
	})
}

func (comp *compiler) addConst(ctx *constContext, pos ast.Pos, name string) {
	if name == "" {
		return
	}
	if _, builtin := comp.builtinConsts[name]; builtin {
		return
	}
	// In case of intN[identA], identA may refer to a constant or to a set of
	// flags. To avoid marking all flags as constants, we must check here
	// whether identA refers to a flag. We have a check in the compiler to
	// ensure an identifier can never refer to both a constant and flags.
	if _, isFlag := comp.intFlags[name]; isFlag {
		return
	}
	ctx.addConst(pos, name, true)
	for _, instantions := range ctx.instantionStack {
		for _, pos1 := range instantions {
			ctx.addConst(pos1, name, true)
		}
	}
}

type constInfo struct {
	consts       map[string]*Const
	defines      map[string]string
	includeArray []string
	incdirArray  []string
}

func (ctx *constContext) addConst(pos ast.Pos, name string, used bool) {
	info := ctx.getConstInfo(pos)
	if c := info.consts[name]; c != nil && c.Used {
		used = true
	}
	info.consts[name] = &Const{
		Pos:  pos,
		Name: name,
		Used: used,
	}
}

func (ctx *constContext) getConstInfo(pos ast.Pos) *constInfo {
	info := ctx.infos[pos.File]
	if info == nil {
		info = &constInfo{
			consts:  make(map[string]*Const),
			defines: make(map[string]string),
		}
		ctx.infos[pos.File] = info
	}
	return info
}

func convertConstInfo(ctx *constContext, metas map[string]Meta) map[string]*ConstInfo {
	res := make(map[string]*ConstInfo)
	for file, info := range ctx.infos {
		if file == ast.BuiltinFile {
			continue
		}
		var allConsts []*Const
		for _, val := range info.consts {
			allConsts = append(allConsts, val)
		}
		sort.Slice(allConsts, func(i, j int) bool {
			return allConsts[i].Name < allConsts[j].Name
		})
		res[file] = &ConstInfo{
			Consts:   allConsts,
			Includes: info.includeArray,
			Incdirs:  info.incdirArray,
			Defines:  info.defines,
		}
	}
	return res
}

// assignSyscallNumbers assigns syscall numbers, discards unsupported syscalls.
func (comp *compiler) assignSyscallNumbers(consts map[string]uint64) {
	for _, decl := range comp.desc.Nodes {
		c, ok := decl.(*ast.Call)
		if !ok || strings.HasPrefix(c.CallName, "syz_") {
			continue
		}
		str := comp.target.SyscallPrefix + c.CallName
		nr, ok := consts[str]
		if ok {
			c.NR = nr
			continue
		}
		c.NR = ^uint64(0) // mark as unused to not generate it
		name := "syscall " + c.CallName
		if !comp.unsupported[name] {
			comp.unsupported[name] = true
			comp.warning(c.Pos, "unsupported syscall: %v due to missing const %v",
				c.CallName, str)
		}
	}
}

// patchConsts replaces all symbolic consts with their numeric values taken from consts map.
// Updates desc and returns set of unsupported syscalls and flags.
func (comp *compiler) patchConsts(consts0 map[string]uint64) {
	consts := make(map[string]uint64)
	for name, val := range consts0 {
		consts[name] = val
	}
	for name, val := range comp.builtinConsts {
		if _, ok := consts[name]; ok {
			panic(fmt.Sprintf("builtin const %v already defined", name))
		}
		consts[name] = val
	}
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.IntFlags:
			// Unsupported flag values are dropped.
			var values []*ast.Int
			for _, v := range n.Values {
				if comp.patchIntConst(v, consts, nil) {
					values = append(values, v)
				}
			}
			n.Values = values
		case *ast.Resource, *ast.Struct, *ast.Call, *ast.TypeDef:
			// Walk whole tree and replace consts in Type's and Int's.
			missing := ""
			comp.foreachType(decl, func(_ *ast.Type, desc *typeDesc,
				args []*ast.Type, _ prog.IntTypeCommon) {
				for i, arg := range args {
					if desc.Args[i].Type.Kind&kindInt != 0 {
						comp.patchTypeConst(arg, consts, &missing)
					}
				}
			})
			switch n := decl.(type) {
			case *ast.Resource:
				for _, v := range n.Values {
					comp.patchIntConst(v, consts, &missing)
				}
			case *ast.Call:
				for _, attr := range n.Attrs {
					if callAttrs[attr.Ident].Type == intAttr {
						comp.patchTypeConst(attr.Args[0], consts, &missing)
					}
				}
			case *ast.Struct:
				for _, attr := range n.Attrs {
					attrDesc := structOrUnionAttrs(n)[attr.Ident]
					if attrDesc.Type == intAttr {
						comp.patchTypeConst(attr.Args[0], consts, &missing)
					}
				}
				foreachFieldAttrConst(n, func(t *ast.Type) {
					comp.patchTypeConst(t, consts, &missing)
				})
			}
			if missing == "" {
				continue
			}
			// Produce a warning about unsupported syscall/resource/struct.
			// TODO(dvyukov): we should transitively remove everything that
			// depends on unsupported things. Potentially we still can get,
			// say, a bad int range error due to the wrong const value.
			// However, if we have a union where one of the options is
			// arch-specific and does not have a const value, it's probably
			// better to remove just that option. But then if we get to 0
			// options in the union, we still need to remove it entirely.
			pos, typ, name := decl.Info()
			if id := typ + " " + name; !comp.unsupported[id] {
				comp.unsupported[id] = true
				comp.warning(pos, "unsupported %v: %v due to missing const %v",
					typ, name, missing)
			}
			if c, ok := decl.(*ast.Call); ok {
				c.NR = ^uint64(0) // mark as unused to not generate it
			}
		}
	}
}

func (comp *compiler) patchIntConst(n *ast.Int, consts map[string]uint64, missing *string) bool {
	return comp.patchConst(&n.Value, &n.Ident, consts, missing, false)
}

func (comp *compiler) patchTypeConst(n *ast.Type, consts map[string]uint64, missing *string) {
	comp.patchConst(&n.Value, &n.Ident, consts, missing, true)
	for _, col := range n.Colon {
		comp.patchConst(&col.Value, &col.Ident, consts, missing, true)
	}
}

func (comp *compiler) patchConst(val *uint64, id *string, consts map[string]uint64, missing *string, reset bool) bool {
	if *id == "" {
		return true
	}
	if v, ok := consts[*id]; ok {
		if reset {
			*id = ""
		}
		*val = v
		return true
	}
	// This check is necessary because in intN[identA], identA may be a
	// constant or a set of flags.
	if _, isFlag := comp.intFlags[*id]; isFlag {
		return true
	}
	if missing != nil && *missing == "" {
		*missing = *id
	}
	// 1 is slightly safer than 0 and allows to work-around e.g. an array size
	// that comes from a const missing on an arch. Also see the TODO in patchConsts.
	*val = 1
	return false
}
