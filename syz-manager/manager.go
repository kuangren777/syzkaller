// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"runtime/debug"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/asset"
	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/pkg/ifaceprobe"
	"github.com/google/syzkaller/pkg/image"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	crash_pkg "github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/runtest"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagDebug  = flag.Bool("debug", false, "dump all VM output to console")
	flagBench  = flag.String("bench", "", "write execution statistics into this file periodically")
	flagMode   = flag.String("mode", ModeFuzzing.Name, modesDescription())
	flagTests  = flag.String("tests", "", "prefix to match test file names (for -mode run-tests)")
	flagLLM    = flag.Bool("llm", false, "enable LLM enhancement for fuzzing") // 添加LLM命令行参数
)

type Manager struct {
	cfg             *mgrconfig.Config
	mode            *Mode
	vmPool          *vm.Pool
	pool            *vm.Dispatcher
	target          *prog.Target
	sysTarget       *targets.Target
	reporter        *report.Reporter
	crashStore      *manager.CrashStore
	serv            rpcserver.Server
	http            *manager.HTTPServer
	servStats       rpcserver.Stats
	corpus          *corpus.Corpus
	corpusDB        *db.DB
	corpusDBMu      sync.Mutex // for concurrent operations on corpusDB
	corpusPreload   chan []fuzzer.Candidate
	firstConnect    atomic.Int64 // unix time, or 0 if not connected
	crashTypes      map[string]bool
	enabledFeatures flatrpc.Feature
	checkDone       atomic.Bool
	reportGenerator *manager.ReportGeneratorWrapper
	fresh           bool
	coverFilters    manager.CoverageFilters

	dash *dashapi.Dashboard
	// This is specifically separated from dash, so that we can keep dash = nil when
	// cfg.DashboardOnlyRepro is set, so that we don't accidentially use dash for anything.
	dashRepro *dashapi.Dashboard

	mu             sync.Mutex
	fuzzer         atomic.Pointer[fuzzer.Fuzzer]
	snapshotSource *queue.Distributor
	phase          int

	disabledHashes   map[string]struct{}
	newRepros        [][]byte
	lastMinCorpus    int
	memoryLeakFrames map[string]bool
	dataRaceFrames   map[string]bool
	saturatedCalls   map[string]bool

	externalReproQueue chan *manager.Crash
	crashes            chan *manager.Crash

	benchMu   sync.Mutex
	benchFile *os.File

	assetStorage *asset.Storage
	fsckChecker  image.FsckChecker

	reproLoop *manager.ReproLoop

	llmEnhancer *LLMEnhancer

	Stats
}

type Mode struct {
	Name                  string
	Description           string
	UseDashboard          bool // the mode connects to dashboard/hub
	LoadCorpus            bool // the mode needs to load the corpus
	ExitAfterMachineCheck bool // exit with 0 status when machine check is done
	// Exit with non-zero status and save the report to workdir/report.json if any kernel crash happens.
	FailOnCrashes bool
	CheckConfig   func(cfg *mgrconfig.Config) error
}

var (
	ModeFuzzing = &Mode{
		Name:         "fuzzing",
		Description:  `the default continuous fuzzing mode`,
		UseDashboard: true,
		LoadCorpus:   true,
	}
	ModeSmokeTest = &Mode{
		Name: "smoke-test",
		Description: `run smoke test for syzkaller+kernel
	The test consists of booting VMs and running some simple test programs
	to ensure that fuzzing can proceed in general. After completing the test
	the process exits and the exit status indicates success/failure.
	If the kernel oopses during testing, the report is saved to workdir/report.json.`,
		ExitAfterMachineCheck: true,
		FailOnCrashes:         true,
	}
	ModeCorpusTriage = &Mode{
		Name: "corpus-triage",
		Description: `triage corpus and exit
	This is useful mostly for benchmarking with testbed.`,
		LoadCorpus: true,
	}
	ModeCorpusRun = &Mode{
		Name:        "corpus-run",
		Description: `continuously run the corpus programs`,
		LoadCorpus:  true,
	}
	ModeRunTests = &Mode{
		Name: "run-tests",
		Description: `run unit tests
	Run sys/os/test/* tests in various modes and print results.`,
	}
	ModeIfaceProbe = &Mode{
		Name: "iface-probe",
		Description: `run dynamic part of kernel interface auto-extraction
	When the probe is finished, manager writes the result to workdir/interfaces.json file and exits.`,
		CheckConfig: func(cfg *mgrconfig.Config) error {
			if cfg.Snapshot {
				return fmt.Errorf("snapshot mode is not supported")
			}
			if cfg.Sandbox != "none" {
				return fmt.Errorf("sandbox \"%v\" is not supported (only \"none\")", cfg.Sandbox)
			}
			if !cfg.Cover {
				return fmt.Errorf("coverage is required")
			}
			return nil
		},
	}

	modes = []*Mode{
		ModeFuzzing,
		ModeSmokeTest,
		ModeCorpusTriage,
		ModeCorpusRun,
		ModeRunTests,
		ModeIfaceProbe,
	}
)

func modesDescription() string {
	desc := "mode of operation, one of:\n"
	for _, mode := range modes {
		desc += fmt.Sprintf(" - %v: %v\n", mode.Name, mode.Description)
	}
	return desc
}

const (
	// Just started, nothing done yet.
	phaseInit = iota
	// Corpus is loaded and machine is checked.
	phaseLoadedCorpus
	// Triaged all inputs from corpus.
	// This is when we start querying hub and minimizing persistent corpus.
	phaseTriagedCorpus
	// Done the first request to hub.
	phaseQueriedHub
	// Triaged all new inputs from hub.
	// This is when we start reproducing crashes.
	phaseTriagedHub
)

func main() {
	flag.Parse()
	if !prog.GitRevisionKnown() {
		log.Fatalf("bad syz-manager build: build with make, run bin/syz-manager")
	}
	log.EnableLogCaching(1000, 1<<20)
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if cfg.DashboardAddr != "" {
		// This lets better distinguish logs of individual syz-manager instances.
		log.SetName(cfg.Name)
	}
	var mode *Mode
	for _, m := range modes {
		if *flagMode == m.Name {
			mode = m
			break
		}
	}
	if mode == nil {
		flag.PrintDefaults()
		log.Fatalf("unknown mode: %v", *flagMode)
	}
	if mode.CheckConfig != nil {
		if err := mode.CheckConfig(cfg); err != nil {
			log.Fatalf("%v mode: %v", mode.Name, err)
		}
	}
	if !mode.UseDashboard {
		cfg.DashboardClient = ""
		cfg.HubClient = ""
	}
	RunManager(mode, cfg)
}

func RunManager(mode *Mode, cfg *mgrconfig.Config) {
	var vmPool *vm.Pool
	if !cfg.VMLess {
		var err error
		vmPool, err = vm.Create(cfg, *flagDebug)
		if err != nil {
			log.Fatalf("%v", err)
		}
		defer vmPool.Close()
	}

	osutil.MkdirAll(cfg.Workdir)

	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	mgr := &Manager{
		cfg:                cfg,
		mode:               mode,
		vmPool:             vmPool,
		corpusPreload:      make(chan []fuzzer.Candidate),
		target:             cfg.Target,
		sysTarget:          cfg.SysTarget,
		reporter:           reporter,
		crashStore:         manager.NewCrashStore(cfg),
		crashTypes:         make(map[string]bool),
		disabledHashes:     make(map[string]struct{}),
		memoryLeakFrames:   make(map[string]bool),
		dataRaceFrames:     make(map[string]bool),
		fresh:              true,
		externalReproQueue: make(chan *manager.Crash, 10),
		crashes:            make(chan *manager.Crash, 10),
		saturatedCalls:     make(map[string]bool),
		reportGenerator:    manager.ReportGeneratorCache(cfg),
	}

	// 测试LLM API是否可用
	if cfg.Experimental.LLMAPIEnabled {
		if err := testLLMAPIAvailability(cfg.Experimental.LLMAPIURL); err != nil {
			log.Errorf("LLM API测试失败: %v", err)
		} else {
			log.Logf(0, "LLM API测试成功，API可用")
		}
	}

	// 保存系统调用信息
	if err := mgr.saveSyscallInfo(); err != nil {
		log.Errorf("保存系统调用信息失败: %v", err)
	}

	if *flagDebug {
		mgr.cfg.Procs = 1
	}
	mgr.http = &manager.HTTPServer{
		// Note that if cfg.HTTP == "", we don't start the server.
		Cfg:        cfg,
		StartTime:  time.Now(),
		CrashStore: mgr.crashStore,
	}

	mgr.initStats()
	if mgr.mode.LoadCorpus {
		go mgr.preloadCorpus()
	} else {
		close(mgr.corpusPreload)
	}

	// Create RPC server for fuzzers.
	mgr.servStats = rpcserver.NewStats()
	rpcCfg := &rpcserver.RemoteConfig{
		Config:  mgr.cfg,
		Manager: mgr,
		Stats:   mgr.servStats,
		Debug:   *flagDebug,
	}
	mgr.serv, err = rpcserver.New(rpcCfg)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}
	if err := mgr.serv.Listen(); err != nil {
		log.Fatalf("failed to start rpc server: %v", err)
	}
	ctx := vm.ShutdownCtx()
	go func() {
		err := mgr.serv.Serve(ctx)
		if err != nil {
			log.Fatalf("%s", err)
		}
	}()
	log.Logf(0, "serving rpc on tcp://%v", mgr.serv.Port())

	if cfg.DashboardAddr != "" {
		opts := []dashapi.DashboardOpts{}
		if cfg.DashboardUserAgent != "" {
			opts = append(opts, dashapi.UserAgent(cfg.DashboardUserAgent))
		}
		dash, err := dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey, opts...)
		if err != nil {
			log.Fatalf("failed to create dashapi connection: %v", err)
		}
		mgr.dashRepro = dash
		if !cfg.DashboardOnlyRepro {
			mgr.dash = dash
		}
	}

	if !cfg.AssetStorage.IsEmpty() {
		mgr.assetStorage, err = asset.StorageFromConfig(cfg.AssetStorage, mgr.dash)
		if err != nil {
			log.Fatalf("failed to init asset storage: %v", err)
		}
	}

	if *flagBench != "" {
		mgr.initBench()
	}

	go mgr.heartbeatLoop()
	if mgr.mode != ModeSmokeTest {
		osutil.HandleInterrupts(vm.Shutdown)
	}
	if mgr.vmPool == nil {
		log.Logf(0, "no VMs started (type=none)")
		log.Logf(0, "you are supposed to start syz-executor manually as:")
		log.Logf(0, "syz-executor runner local manager.ip %v", mgr.serv.Port())
		<-vm.Shutdown
		return
	}
	mgr.pool = vm.NewDispatcher(mgr.vmPool, mgr.fuzzerInstance)
	mgr.http.Pool = mgr.pool
	reproVMs := max(0, mgr.vmPool.Count()-mgr.cfg.FuzzingVMs)
	mgr.reproLoop = manager.NewReproLoop(mgr, reproVMs, mgr.cfg.DashboardOnlyRepro)
	mgr.http.ReproLoop = mgr.reproLoop
	mgr.http.TogglePause = mgr.pool.TogglePause

	if mgr.cfg.HTTP != "" {
		go func() {
			err := mgr.http.Serve(ctx)
			if err != nil {
				log.Fatalf("failed to serve HTTP: %v", err)
			}
		}()
	}
	go mgr.trackUsedFiles()
	go mgr.processFuzzingResults(ctx)
	mgr.pool.Loop(ctx)
}

// Exit successfully in special operation modes.
func (mgr *Manager) exit(reason string) {
	log.Logf(0, "%v finished, shutting down...", reason)
	mgr.writeBench()
	close(vm.Shutdown)
	time.Sleep(10 * time.Second)
	os.Exit(0)
}

func (mgr *Manager) heartbeatLoop() {
	lastTime := time.Now()
	for now := range time.NewTicker(10 * time.Second).C {
		diff := int(now.Sub(lastTime))
		lastTime = now
		if mgr.firstConnect.Load() == 0 {
			continue
		}
		mgr.statFuzzingTime.Add(diff * mgr.servStats.StatNumFuzzing.Val())
		buf := new(bytes.Buffer)
		for _, stat := range stat.Collect(stat.Console) {
			fmt.Fprintf(buf, "%v=%v ", stat.Name, stat.Value)
		}
		log.Logf(0, "%s", buf.String())
	}
}

func (mgr *Manager) initBench() {
	f, err := os.OpenFile(*flagBench, os.O_WRONLY|os.O_CREATE|os.O_EXCL, osutil.DefaultFilePerm)
	if err != nil {
		log.Fatalf("failed to open bench file: %v", err)
	}
	mgr.benchFile = f
	go func() {
		for range time.NewTicker(time.Minute).C {
			mgr.writeBench()
		}
	}()
}

func (mgr *Manager) writeBench() {
	if mgr.benchFile == nil {
		return
	}
	mgr.benchMu.Lock()
	defer mgr.benchMu.Unlock()
	vals := make(map[string]int)
	for _, stat := range stat.Collect(stat.All) {
		vals[stat.Name] = stat.V
	}
	data, err := json.MarshalIndent(vals, "", "  ")
	if err != nil {
		log.Fatalf("failed to serialize bench data")
	}
	if _, err := mgr.benchFile.Write(append(data, '\n')); err != nil {
		log.Fatalf("failed to write bench data")
	}
}

func (mgr *Manager) processFuzzingResults(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case crash := <-mgr.crashes:
			needRepro := mgr.saveCrash(crash)
			if mgr.cfg.Reproduce && needRepro {
				mgr.reproLoop.Enqueue(crash)
			}
		case err := <-mgr.pool.BootErrors:
			crash := mgr.convertBootError(err)
			if crash != nil {
				mgr.saveCrash(crash)
			}
		case crash := <-mgr.externalReproQueue:
			if mgr.NeedRepro(crash) {
				mgr.reproLoop.Enqueue(crash)
			}
		}
	}
}

func (mgr *Manager) convertBootError(err error) *manager.Crash {
	var bootErr vm.BootErrorer
	if errors.As(err, &bootErr) {
		title, output := bootErr.BootError()
		rep := mgr.reporter.Parse(output)
		if rep != nil && rep.Type == crash_pkg.UnexpectedReboot {
			// Avoid detecting any boot crash as "unexpected kernel reboot".
			rep = mgr.reporter.ParseFrom(output, rep.SkipPos)
		}
		if rep == nil {
			rep = &report.Report{
				Title:  title,
				Output: output,
			}
		}
		return &manager.Crash{
			Report: rep,
		}
	}
	return nil
}

func reportReproError(err error) {
	shutdown := false
	select {
	case <-vm.Shutdown:
		shutdown = true
	default:
	}

	if errors.Is(err, repro.ErrEmptyCrashLog) {
		// The kernel could have crashed before we executed any programs.
		log.Logf(0, "repro failed: %v", err)
		return
	} else if errors.Is(err, repro.ErrNoVMs) {
		// This error is to be expected if we're shutting down.
		if shutdown {
			return
		}
	}
	// Report everything else as errors.
	log.Errorf("repro failed: %v", err)
}

func (mgr *Manager) RunRepro(crash *manager.Crash) *manager.ReproResult {
	res, stats, err := repro.Run(context.Background(), crash.Output, repro.Environment{
		Config:   mgr.cfg,
		Features: mgr.enabledFeatures,
		Reporter: mgr.reporter,
		Pool:     mgr.pool,
	})
	ret := &manager.ReproResult{
		Crash: crash,
		Repro: res,
		Stats: stats,
		Err:   err,
	}
	if err == nil && res != nil && mgr.cfg.StraceBin != "" {
		const straceAttempts = 2
		for i := 1; i <= straceAttempts; i++ {
			strace := repro.RunStrace(res, mgr.cfg, mgr.reporter, mgr.pool)
			sameBug := strace.IsSameBug(res)
			log.Logf(0, "strace run attempt %d/%d for '%s': same bug %v, error %v",
				i, straceAttempts, res.Report.Title, sameBug, strace.Error)
			// We only want to save strace output if it resulted in the same bug.
			// Otherwise, it will be hard to reproduce on syzbot and will confuse users.
			if sameBug {
				ret.Strace = strace
				break
			}
		}
	}

	mgr.processRepro(ret)

	return ret
}

func (mgr *Manager) processRepro(res *manager.ReproResult) {
	if res.Err != nil {
		reportReproError(res.Err)
	}
	if res.Repro == nil {
		if res.Crash.Title == "" {
			log.Logf(1, "repro '%v' not from dashboard, so not reporting the failure",
				res.Crash.FullTitle())
		} else {
			log.Logf(1, "report repro failure of '%v'", res.Crash.Title)
			mgr.saveFailedRepro(res.Crash.Report, res.Stats)
		}
	} else {
		mgr.saveRepro(res)
	}
}

func (mgr *Manager) preloadCorpus() {
	info, err := manager.LoadSeeds(mgr.cfg, false)
	if err != nil {
		log.Fatalf("failed to load corpus: %v", err)
	}
	mgr.fresh = info.Fresh
	mgr.corpusDB = info.CorpusDB
	mgr.corpusPreload <- info.Candidates
}

func (mgr *Manager) loadCorpus(enabledSyscalls map[*prog.Syscall]bool) []fuzzer.Candidate {
	ret := manager.FilterCandidates(<-mgr.corpusPreload, enabledSyscalls, true)
	if mgr.cfg.PreserveCorpus {
		for _, hash := range ret.ModifiedHashes {
			// This program contains a disabled syscall.
			// We won't execute it, but remember its hash so
			// it is not deleted during minimization.
			mgr.disabledHashes[hash] = struct{}{}
		}
	}
	// Let's favorize smaller programs, otherwise the poorly minimized ones may overshadow the rest.
	sort.SliceStable(ret.Candidates, func(i, j int) bool {
		return len(ret.Candidates[i].Prog.Calls) < len(ret.Candidates[j].Prog.Calls)
	})
	reminimized := ret.ReminimizeSubset()
	resmashed := ret.ResmashSubset()
	log.Logf(0, "%-24v: %v (%v seeds), %d to be reminimized, %d to be resmashed",
		"corpus", len(ret.Candidates), ret.SeedCount, reminimized, resmashed)
	return ret.Candidates
}

func (mgr *Manager) fuzzerInstance(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
	mgr.mu.Lock()
	serv := mgr.serv
	mgr.mu.Unlock()
	if serv == nil {
		// We're in the process of switching off the RPCServer.
		return
	}
	injectExec := make(chan bool, 10)
	errChan := serv.CreateInstance(inst.Index(), injectExec, updInfo)

	// LLM配置，设置默认值
	var llmConfig *fuzzer.LLMConfig
	if mgr.cfg.Experimental.LLMAPIEnabled {
		// 使用OpenAI标准格式的API URL
		apiURL := mgr.cfg.Experimental.LLMAPIURL
		if apiURL == "" {
			apiURL = "http://100.64.88.112:5231"
		}

		llmConfig = &fuzzer.LLMConfig{
			Enabled:         true,
			APIURL:          apiURL,
			StallThreshold:  mgr.cfg.Experimental.LLMStallThreshold,
			UsageFrequency:  mgr.cfg.Experimental.LLMUsageFrequency,
			UseOpenAIFormat: true, // 使用OpenAI标准格式
		}
		// 设置默认值
		if llmConfig.StallThreshold == 0 {
			llmConfig.StallThreshold = 1000
		}
		if llmConfig.UsageFrequency == 0 {
			llmConfig.UsageFrequency = 10
		}
		log.Logf(0, "LLM API 已启用: URL=%v, 使用OpenAI格式, 阈值=%v, 频率=%v%%",
			llmConfig.APIURL, llmConfig.StallThreshold, llmConfig.UsageFrequency)

		// 将LLMConfig添加到当前运行的fuzzer实例中
		mgr.mu.Lock()
		if fuzzerObj := mgr.fuzzer.Load(); fuzzerObj != nil {
			fuzzerObj.Config.LLMConfig = llmConfig
			log.Logf(0, "已将LLMConfig添加到当前运行的fuzzer实例")
		}
		mgr.mu.Unlock()
	}

	// 创建一个done通道，当函数返回时关闭
	done := make(chan struct{})
	defer close(done)

	// 在后台检查实例创建是否有错误
	var instanceErr error
	go func() {
		select {
		case err := <-errChan:
			if err != nil {
				instanceErr = err
				log.Errorf("实例创建失败: %v", err)
			}
		case <-done:
			// 函数已返回，不需要再检查错误
		}
	}()

	// 继续原来的逻辑
	rep, vmInfo, err := mgr.runInstanceInner(ctx, inst, injectExec, vm.EarlyFinishCb(func() {
		// Depending on the crash type and kernel config, fuzzing may continue
		// running for several seconds even after kernel has printed a crash report.
		// This litters the log and we want to prevent it.
		serv.StopFuzzing(inst.Index())
	}))
	var extraExecs []report.ExecutorInfo
	if rep != nil && rep.Executor != nil {
		extraExecs = []report.ExecutorInfo{*rep.Executor}
	}
	lastExec, machineInfo := serv.ShutdownInstance(inst.Index(), rep != nil, extraExecs...)
	if rep != nil {
		rpcserver.PrependExecuting(rep, lastExec)
		if len(vmInfo) != 0 {
			machineInfo = append(append(vmInfo, '\n'), machineInfo...)
		}
		rep.MachineInfo = machineInfo
	}
	if err == nil && rep != nil {
		mgr.crashes <- &manager.Crash{
			InstanceIndex: inst.Index(),
			Report:        rep,
		}
	}
	if err != nil {
		log.Errorf("#%d 运行失败: %v", inst.Index(), err)
	} else if instanceErr != nil {
		log.Errorf("#%d 实例错误: %v", inst.Index(), instanceErr)
	}
}

func (mgr *Manager) runInstanceInner(ctx context.Context, inst *vm.Instance, injectExec <-chan bool,
	finishCb vm.EarlyFinishCb) (*report.Report, []byte, error) {
	fwdAddr, err := inst.Forward(mgr.serv.Port())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup port forwarding: %w", err)
	}

	// If ExecutorBin is provided, it means that syz-executor is already in the image,
	// so no need to copy it.
	executorBin := mgr.sysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = inst.Copy(mgr.cfg.ExecutorBin)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	// 创建LLM配置对象，但不通过命令行传递
	var env []string
	if mgr.cfg.Experimental.LLMAPIEnabled {
		apiURL := mgr.cfg.Experimental.LLMAPIURL
		if apiURL == "" {
			apiURL = "http://100.64.88.112:5231"
		}
		llmConfig := &fuzzer.LLMConfig{
			Enabled:         true,
			APIURL:          apiURL,
			StallThreshold:  mgr.cfg.Experimental.LLMStallThreshold,
			UsageFrequency:  mgr.cfg.Experimental.LLMUsageFrequency,
			UseOpenAIFormat: true,
		}
		// 设置默认值
		if llmConfig.StallThreshold == 0 {
			llmConfig.StallThreshold = 1000
		}
		if llmConfig.UsageFrequency == 0 {
			llmConfig.UsageFrequency = 10
		}

		// 通过环境变量传递LLM配置
		env = append(env, fmt.Sprintf("SYZ_LLM_ENABLED=1"))
		env = append(env, fmt.Sprintf("SYZ_LLM_API_URL=%s", llmConfig.APIURL))
		env = append(env, fmt.Sprintf("SYZ_LLM_STALL_THRESHOLD=%d", llmConfig.StallThreshold))
		env = append(env, fmt.Sprintf("SYZ_LLM_USAGE_FREQUENCY=%d", llmConfig.UsageFrequency))
		env = append(env, fmt.Sprintf("SYZ_LLM_USE_OPENAI_FORMAT=1"))

		log.Logf(0, "在VM %v中启用LLM配置: URL=%v, 使用OpenAI格式, 阈值=%v, 频率=%v%%",
			inst.Index(), llmConfig.APIURL, llmConfig.StallThreshold, llmConfig.UsageFrequency)
	}

	// Run the fuzzer binary.
	start := time.Now()

	host, port, err := net.SplitHostPort(fwdAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse manager's address")
	}

	// 恢复原始命令行格式
	cmd := fmt.Sprintf("%v runner %v %v %v", executorBin, inst.Index(), host, port)
	log.Logf(1, "运行命令: %s (添加环境变量: %v)", cmd, env)

	// 使用vm.SetEnv将环境变量传递
	opts := []any{
		vm.ExitTimeout,
		vm.StopContext(ctx),
		vm.InjectExecuting(injectExec),
		finishCb,
	}
	if len(env) > 0 {
		opts = append(opts, vm.SetEnv(env))
	}

	// 传递环境变量
	_, rep, err := inst.Run(mgr.cfg.Timeouts.VMRunningTime, mgr.reporter, cmd, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run fuzzer: %w", err)
	}
	if rep == nil {
		// This is the only "OK" outcome.
		log.Logf(0, "VM %v: running for %v, restarting", inst.Index(), time.Since(start))
		return nil, nil, nil
	}
	vmInfo, err := inst.Info()
	if err != nil {
		vmInfo = []byte(fmt.Sprintf("error getting VM info: %v\n", err))
	}
	return rep, vmInfo, nil
}

func (mgr *Manager) emailCrash(crash *manager.Crash) {
	if len(mgr.cfg.EmailAddrs) == 0 {
		return
	}
	args := []string{"-s", "syzkaller: " + crash.Title}
	args = append(args, mgr.cfg.EmailAddrs...)
	log.Logf(0, "sending email to %v", mgr.cfg.EmailAddrs)

	cmd := exec.Command("mailx", args...)
	cmd.Stdin = bytes.NewReader(crash.Report.Report)
	if _, err := osutil.Run(10*time.Minute, cmd); err != nil {
		log.Logf(0, "failed to send email: %v", err)
	}
}

func (mgr *Manager) saveCrash(crash *manager.Crash) bool {
	if err := mgr.reporter.Symbolize(crash.Report); err != nil {
		log.Errorf("failed to symbolize report: %v", err)
	}
	if crash.Type == crash_pkg.MemoryLeak {
		mgr.mu.Lock()
		mgr.memoryLeakFrames[crash.Frame] = true
		mgr.mu.Unlock()
	}
	if crash.Type == crash_pkg.DataRace {
		mgr.mu.Lock()
		mgr.dataRaceFrames[crash.Frame] = true
		mgr.mu.Unlock()
	}
	flags := ""
	if crash.Corrupted {
		flags += " [corrupted]"
	}
	if crash.Suppressed {
		flags += " [suppressed]"
	}
	log.Logf(0, "VM %v: crash: %v%v", crash.InstanceIndex, crash.Title, flags)

	if mgr.mode.FailOnCrashes {
		path := filepath.Join(mgr.cfg.Workdir, "report.json")
		if err := osutil.WriteJSON(path, crash.Report); err != nil {
			log.Fatal(err)
		}
		log.Fatalf("kernel crashed in smoke testing mode, exiting")
	}

	if crash.Suppressed {
		// Collect all of them into a single bucket so that it's possible to control and assess them,
		// e.g. if there are some spikes in suppressed reports.
		crash.Title = "suppressed report"
		mgr.statSuppressed.Add(1)
	}

	mgr.statCrashes.Add(1)
	mgr.mu.Lock()
	if !mgr.crashTypes[crash.Title] {
		mgr.crashTypes[crash.Title] = true
		mgr.statCrashTypes.Add(1)
	}
	mgr.mu.Unlock()

	if mgr.dash != nil {
		if crash.Type == crash_pkg.MemoryLeak {
			return true
		}
		dc := &dashapi.Crash{
			BuildID:     mgr.cfg.Tag,
			Title:       crash.Title,
			AltTitles:   crash.AltTitles,
			Corrupted:   crash.Corrupted,
			Suppressed:  crash.Suppressed,
			Recipients:  crash.Recipients.ToDash(),
			Log:         crash.Output,
			Report:      crash.Report.Report,
			MachineInfo: crash.MachineInfo,
		}
		setGuiltyFiles(dc, crash.Report)
		resp, err := mgr.dash.ReportCrash(dc)
		if err != nil {
			log.Logf(0, "failed to report crash to dashboard: %v", err)
		}
		// Don't store the crash locally even if we failed to upload it.
		// There is 0 chance that one will ever look in the crashes/ folder of those instances.
		return mgr.cfg.Reproduce && resp.NeedRepro
	}
	first, err := mgr.crashStore.SaveCrash(crash)
	if err != nil {
		log.Logf(0, "failed to save the cash: %v", err)
		return false
	}
	if first {
		go mgr.emailCrash(crash)
	}
	return mgr.NeedRepro(crash)
}

func (mgr *Manager) needLocalRepro(crash *manager.Crash) bool {
	if !mgr.cfg.Reproduce || crash.Corrupted || crash.Suppressed {
		return false
	}
	if mgr.crashStore.HasRepro(crash.Title) {
		return false
	}
	return mgr.crashStore.MoreReproAttempts(crash.Title)
}

func (mgr *Manager) NeedRepro(crash *manager.Crash) bool {
	if !mgr.cfg.Reproduce {
		return false
	}
	if crash.FromHub || crash.FromDashboard {
		return true
	}
	mgr.mu.Lock()
	phase, features := mgr.phase, mgr.enabledFeatures
	mgr.mu.Unlock()
	if phase < phaseLoadedCorpus || (features&flatrpc.FeatureLeak != 0 &&
		crash.Type != crash_pkg.MemoryLeak) {
		// Leak checking is very slow, don't bother reproducing other crashes on leak instance.
		return false
	}
	if mgr.dashRepro == nil {
		return mgr.needLocalRepro(crash)
	}
	cid := &dashapi.CrashID{
		BuildID:    mgr.cfg.Tag,
		Title:      crash.Title,
		Corrupted:  crash.Corrupted,
		Suppressed: crash.Suppressed,
		// When cfg.DashboardOnlyRepro is enabled, we don't sent any reports to dashboard.
		// We also don't send leak reports w/o reproducers to dashboard, so they may be missing.
		MayBeMissing: mgr.dash == nil || crash.Type == crash_pkg.MemoryLeak,
	}
	needRepro, err := mgr.dashRepro.NeedRepro(cid)
	if err != nil {
		log.Logf(0, "dashboard.NeedRepro failed: %v", err)
	}
	return needRepro
}

func truncateReproLog(log []byte) []byte {
	// Repro logs can get quite large and we have trouble sending large API requests (see #4495).
	// Let's truncate the log to a 512KB prefix and 512KB suffix.
	return report.Truncate(log, 512000, 512000)
}

func (mgr *Manager) saveFailedRepro(rep *report.Report, stats *repro.Stats) {
	reproLog := stats.FullLog()
	if mgr.dash != nil {
		if rep.Type == crash_pkg.MemoryLeak {
			// Don't send failed leak repro attempts to dashboard
			// as we did not send the crash itself.
			log.Logf(1, "failed repro of '%v': not sending because of the memleak type", rep.Title)
			return
		}
		cid := &dashapi.CrashID{
			BuildID:      mgr.cfg.Tag,
			Title:        rep.Title,
			Corrupted:    rep.Corrupted,
			Suppressed:   rep.Suppressed,
			MayBeMissing: rep.Type == crash_pkg.MemoryLeak,
			ReproLog:     truncateReproLog(reproLog),
		}
		if err := mgr.dash.ReportFailedRepro(cid); err != nil {
			log.Logf(0, "failed to report failed repro to dashboard (log size %d): %v",
				len(reproLog), err)
		}
		return
	}
	err := mgr.crashStore.SaveFailedRepro(rep.Title, reproLog)
	if err != nil {
		log.Logf(0, "failed to save repro log for %q: %v", rep.Title, err)
	}
}

func (mgr *Manager) saveRepro(res *manager.ReproResult) {
	repro := res.Repro
	opts := fmt.Sprintf("# %+v\n", repro.Opts)
	progText := repro.Prog.Serialize()

	// Append this repro to repro list to send to hub if it didn't come from hub originally.
	if !res.Crash.FromHub {
		progForHub := []byte(fmt.Sprintf("# %+v\n# %v\n# %v\n%s",
			repro.Opts, repro.Report.Title, mgr.cfg.Tag, progText))
		mgr.mu.Lock()
		mgr.newRepros = append(mgr.newRepros, progForHub)
		mgr.mu.Unlock()
	}

	var cprogText []byte
	if repro.CRepro {
		cprog, err := csource.Write(repro.Prog, repro.Opts)
		if err == nil {
			formatted, err := csource.Format(cprog)
			if err == nil {
				cprog = formatted
			}
			cprogText = cprog
		} else {
			log.Logf(0, "failed to write C source: %v", err)
		}
	}

	if mgr.dash != nil {
		// Note: we intentionally don't set Corrupted for reproducers:
		// 1. This is reproducible so can be debugged even with corrupted report.
		// 2. Repro re-tried 3 times and still got corrupted report at the end,
		//    so maybe corrupted report detection is broken.
		// 3. Reproduction is expensive so it's good to persist the result.

		report := repro.Report
		output := report.Output

		var crashFlags dashapi.CrashFlags
		if res.Strace != nil {
			// If syzkaller managed to successfully run the repro with strace, send
			// the report and the output generated under strace.
			report = res.Strace.Report
			output = res.Strace.Output
			crashFlags = dashapi.CrashUnderStrace
		}

		dc := &dashapi.Crash{
			BuildID:       mgr.cfg.Tag,
			Title:         report.Title,
			AltTitles:     report.AltTitles,
			Suppressed:    report.Suppressed,
			Recipients:    report.Recipients.ToDash(),
			Log:           output,
			Flags:         crashFlags,
			Report:        report.Report,
			ReproOpts:     repro.Opts.Serialize(),
			ReproSyz:      progText,
			ReproC:        cprogText,
			ReproLog:      truncateReproLog(res.Stats.FullLog()),
			Assets:        mgr.uploadReproAssets(repro),
			OriginalTitle: res.Crash.Title,
		}
		setGuiltyFiles(dc, report)
		if _, err := mgr.dash.ReportCrash(dc); err != nil {
			log.Logf(0, "failed to report repro to dashboard: %v", err)
		} else {
			// Don't store the crash locally, if we've successfully
			// uploaded it to the dashboard. These will just eat disk space.
			return
		}
	}
	err := mgr.crashStore.SaveRepro(res, append([]byte(opts), progText...), cprogText)
	if err != nil {
		log.Logf(0, "%s", err)
	}
}

func (mgr *Manager) ResizeReproPool(size int) {
	mgr.pool.ReserveForRun(size)
}

func (mgr *Manager) uploadReproAssets(repro *repro.Result) []dashapi.NewAsset {
	if mgr.assetStorage == nil {
		return nil
	}

	ret := []dashapi.NewAsset{}
	repro.Prog.ForEachAsset(func(name string, typ prog.AssetType, r io.Reader, c *prog.Call) {
		dashTyp, ok := map[prog.AssetType]dashapi.AssetType{
			prog.MountInRepro: dashapi.MountInRepro,
		}[typ]
		if !ok {
			panic("unknown extracted prog asset")
		}
		r2 := &bytes.Buffer{}
		r1 := io.TeeReader(r, r2)
		asset, err := mgr.assetStorage.UploadCrashAsset(r1, name, dashTyp, nil)
		if err != nil {
			log.Logf(1, "processing of the asset %v (%v) failed: %v", name, typ, err)
			return
		}
		// Report file systems that fail fsck with a separate tag.
		if mgr.cfg.RunFsck && dashTyp == dashapi.MountInRepro &&
			c.Meta.Attrs.Fsck != "" && mgr.fsckChecker.Exists(c.Meta.Attrs.Fsck) {
			logs, isClean, err := image.Fsck(r2, c.Meta.Attrs.Fsck)
			if err != nil {
				log.Errorf("fsck of the asset %v failed: %v", name, err)
			} else {
				asset.FsckLog = logs
				asset.FsIsClean = isClean
			}
		}
		ret = append(ret, asset)
	})
	return ret
}

func (mgr *Manager) corpusInputHandler(updates <-chan corpus.NewItemEvent) {
	for update := range updates {
		if len(update.NewCover) != 0 && mgr.coverFilters.ExecutorFilter != nil {
			filtered := 0
			for _, pc := range update.NewCover {
				if _, ok := mgr.coverFilters.ExecutorFilter[pc]; ok {
					filtered++
				}
			}
			mgr.statCoverFiltered.Add(filtered)
		}
		if update.Exists {
			// We only save new progs into the corpus.db file.
			continue
		}
		mgr.corpusDBMu.Lock()
		mgr.corpusDB.Save(update.Sig, update.ProgData, 0)
		if err := mgr.corpusDB.Flush(); err != nil {
			log.Errorf("failed to save corpus database: %v", err)
		}
		mgr.corpusDBMu.Unlock()
	}
}

func (mgr *Manager) getMinimizedCorpus() []*corpus.Item {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.minimizeCorpusLocked()
	return mgr.corpus.Items()
}

func (mgr *Manager) getNewRepros() [][]byte {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	repros := mgr.newRepros
	mgr.newRepros = nil
	return repros
}

func (mgr *Manager) addNewCandidates(candidates []fuzzer.Candidate) {
	mgr.mu.Lock()
	if mgr.phase == phaseTriagedCorpus {
		mgr.setPhaseLocked(phaseQueriedHub)
	}
	mgr.mu.Unlock()
	if mgr.cfg.Experimental.ResetAccState {
		// Don't accept new candidates -- the execution is already very slow,
		// syz-hub will just overwhelm us.
		return
	}
	mgr.fuzzer.Load().AddCandidates(candidates)
}

func (mgr *Manager) minimizeCorpusLocked() {
	// Don't minimize corpus until we have triaged all inputs from it.
	// During corpus triage it would happen very often since we are actively adding inputs,
	// and presumably the persistent corpus was reasonably minimial, and we don't use it for fuzzing yet.
	if mgr.phase < phaseTriagedCorpus {
		return
	}
	currSize := mgr.corpus.StatProgs.Val()
	if currSize <= mgr.lastMinCorpus*103/100 {
		return
	}
	mgr.corpus.Minimize(mgr.cfg.Cover)
	newSize := mgr.corpus.StatProgs.Val()

	log.Logf(1, "minimized corpus: %v -> %v", currSize, newSize)
	mgr.lastMinCorpus = newSize

	// From time to time we get corpus explosion due to different reason:
	// generic bugs, per-OS bugs, problems with fallback coverage, kcov bugs, etc.
	// This has bad effect on the instance and especially on instances
	// connected via hub. Do some per-syscall sanity checking to prevent this.
	for call, info := range mgr.corpus.CallCover() {
		if mgr.cfg.Cover {
			// If we have less than 1K inputs per this call,
			// accept all new inputs unconditionally.
			if info.Count < 1000 {
				continue
			}
			// If we have more than 3K already, don't accept any more.
			// Between 1K and 3K look at amount of coverage we are getting from these programs.
			// Empirically, real coverage for the most saturated syscalls is ~30-60
			// per program (even when we have a thousand of them). For explosion
			// case coverage tend to be much lower (~0.3-5 per program).
			if info.Count < 3000 && len(info.Cover)/info.Count >= 10 {
				continue
			}
		} else {
			// If we don't have real coverage, signal is weak.
			// If we have more than several hundreds, there is something wrong.
			if info.Count < 300 {
				continue
			}
		}
		if mgr.saturatedCalls[call] {
			continue
		}
		mgr.saturatedCalls[call] = true
		log.Logf(0, "coverage for %v has saturated, not accepting more inputs", call)
	}

	mgr.corpusDBMu.Lock()
	defer mgr.corpusDBMu.Unlock()
	for key := range mgr.corpusDB.Records {
		ok1 := mgr.corpus.Item(key) != nil
		_, ok2 := mgr.disabledHashes[key]
		if !ok1 && !ok2 {
			mgr.corpusDB.Delete(key)
		}
	}
	if err := mgr.corpusDB.Flush(); err != nil {
		log.Fatalf("failed to save corpus database: %v", err)
	}
	mgr.corpusDB.BumpVersion(manager.CurrentDBVersion)
}

func setGuiltyFiles(crash *dashapi.Crash, report *report.Report) {
	if report.GuiltyFile != "" {
		crash.GuiltyFiles = []string{report.GuiltyFile}
	}
}

func (mgr *Manager) BugFrames() (leaks, races []string) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	for frame := range mgr.memoryLeakFrames {
		leaks = append(leaks, frame)
	}
	for frame := range mgr.dataRaceFrames {
		races = append(races, frame)
	}
	return
}

func (mgr *Manager) MachineChecked(features flatrpc.Feature,
	enabledSyscalls map[*prog.Syscall]bool) (queue.Source, error) {
	if len(enabledSyscalls) == 0 {
		return nil, fmt.Errorf("all system calls are disabled")
	}
	if mgr.mode.ExitAfterMachineCheck {
		mgr.exit(mgr.mode.Name)
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if mgr.phase != phaseInit {
		panic("machineChecked() called not during phaseInit")
	}
	if mgr.checkDone.Swap(true) {
		panic("MachineChecked called twice")
	}
	mgr.enabledFeatures = features
	mgr.http.EnabledSyscalls.Store(enabledSyscalls)
	mgr.firstConnect.Store(time.Now().Unix())
	statSyscalls := stat.New("syscalls", "Number of enabled syscalls",
		stat.Simple, stat.NoGraph, stat.Link("/syscalls"))
	statSyscalls.Add(len(enabledSyscalls))
	candidates := mgr.loadCorpus(enabledSyscalls)
	mgr.setPhaseLocked(phaseLoadedCorpus)
	opts := fuzzer.DefaultExecOpts(mgr.cfg, features, *flagDebug)

	// 创建LLMConfig对象
	var llmConfig *fuzzer.LLMConfig
	if mgr.cfg.Experimental.LLMAPIEnabled {
		apiURL := mgr.cfg.Experimental.LLMAPIURL
		if apiURL == "" {
			apiURL = "http://100.64.88.112:5231"
		}
		llmConfig = &fuzzer.LLMConfig{
			Enabled:         true,
			APIURL:          apiURL,
			StallThreshold:  mgr.cfg.Experimental.LLMStallThreshold,
			UsageFrequency:  mgr.cfg.Experimental.LLMUsageFrequency,
			UseOpenAIFormat: true,
		}
		// 设置默认值
		if llmConfig.StallThreshold == 0 {
			llmConfig.StallThreshold = 1000
		}
		if llmConfig.UsageFrequency == 0 {
			llmConfig.UsageFrequency = 10
		}
		log.Logf(0, "创建LLMConfig: URL=%v, 使用OpenAI格式=true, 阈值=%v, 频率=%v%%",
			llmConfig.APIURL, llmConfig.StallThreshold, llmConfig.UsageFrequency)
	} else {
		log.Logf(0, "LLM API未启用，不创建LLMConfig")
	}

	if mgr.mode == ModeFuzzing || mgr.mode == ModeCorpusTriage {
		corpusUpdates := make(chan corpus.NewItemEvent, 128)
		mgr.corpus = corpus.NewFocusedCorpus(context.Background(),
			corpusUpdates, mgr.coverFilters.Areas)
		mgr.http.Corpus.Store(mgr.corpus)

		rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		fuzzerConfig := &fuzzer.Config{
			Corpus:         mgr.corpus,
			Snapshot:       mgr.cfg.Snapshot,
			Coverage:       mgr.cfg.Cover,
			FaultInjection: features&flatrpc.FeatureFault != 0,
			Comparisons:    features&flatrpc.FeatureComparisons != 0,
			Collide:        true,
			EnabledCalls:   enabledSyscalls,
			NoMutateCalls:  mgr.cfg.NoMutateCalls,
			FetchRawCover:  mgr.cfg.RawCover,
			LLMConfig:      llmConfig, // 设置LLMConfig
			Logf: func(level int, msg string, args ...interface{}) {
				if level != 0 {
					return
				}
				log.Logf(level, msg, args...)
			},
			NewInputFilter: func(call string) bool {
				mgr.mu.Lock()
				defer mgr.mu.Unlock()
				return !mgr.saturatedCalls[call]
			},
		}

		// 记录创建的配置情况
		log.Logf(0, "创建fuzzerConfig: LLMConfig=%v", fuzzerConfig.LLMConfig != nil)

		fuzzerObj := fuzzer.NewFuzzer(context.Background(), fuzzerConfig, rnd, mgr.target)
		fuzzerObj.AddCandidates(candidates)
		mgr.fuzzer.Store(fuzzerObj)
		mgr.http.Fuzzer.Store(fuzzerObj)

		go mgr.corpusInputHandler(corpusUpdates)
		go mgr.corpusMinimization()
		go mgr.fuzzerLoop(fuzzerObj)
		if mgr.dash != nil {
			go mgr.dashboardReporter()
			if mgr.cfg.Reproduce {
				go mgr.dashboardReproTasks()
			}
		}
		source := queue.DefaultOpts(fuzzerObj, opts)
		if mgr.cfg.Snapshot {
			log.Logf(0, "restarting VMs for snapshot mode")
			mgr.snapshotSource = queue.Distribute(source)
			mgr.pool.SetDefault(mgr.snapshotInstance)
			mgr.serv.Close()
			mgr.serv = nil
			return queue.Callback(func() *queue.Request {
				return nil
			}), nil
		}
		return source, nil
	} else if mgr.mode == ModeCorpusRun {
		ctx := &corpusRunner{
			candidates: candidates,
			rnd:        rand.New(rand.NewSource(time.Now().UnixNano())),
		}
		return queue.DefaultOpts(ctx, opts), nil
	} else if mgr.mode == ModeRunTests {
		ctx := &runtest.Context{
			Dir:      filepath.Join(mgr.cfg.Syzkaller, "sys", mgr.cfg.Target.OS, "test"),
			Target:   mgr.cfg.Target,
			Features: features,
			EnabledCalls: map[string]map[*prog.Syscall]bool{
				mgr.cfg.Sandbox: enabledSyscalls,
			},
			LogFunc: func(text string) { fmt.Println(text) },
			Verbose: true,
			Debug:   *flagDebug,
			Tests:   *flagTests,
		}
		ctx.Init()
		go func() {
			err := ctx.Run(context.Background())
			if err != nil {
				log.Fatal(err)
			}
			mgr.exit("tests")
		}()
		return ctx, nil
	} else if mgr.mode == ModeIfaceProbe {
		exec := queue.Plain()
		go func() {
			res, err := ifaceprobe.Run(vm.ShutdownCtx(), mgr.cfg, features, exec)
			if err != nil {
				log.Fatalf("interface probing failed: %v", err)
			}
			path := filepath.Join(mgr.cfg.Workdir, "interfaces.json")
			if err := osutil.WriteJSON(path, res); err != nil {
				log.Fatal(err)
			}
			mgr.exit("interface probe")
		}()
		return exec, nil
	}
	panic(fmt.Sprintf("unexpected mode %q", mgr.mode.Name))
}

type corpusRunner struct {
	candidates []fuzzer.Candidate
	mu         sync.Mutex
	rnd        *rand.Rand
	seq        int
}

func (cr *corpusRunner) Next() *queue.Request {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	var p *prog.Prog
	if cr.seq < len(cr.candidates) {
		// First run all candidates sequentially.
		p = cr.candidates[cr.seq].Prog
		cr.seq++
	} else {
		// Then pick random progs.
		p = cr.candidates[cr.rnd.Intn(len(cr.candidates))].Prog
	}
	return &queue.Request{
		Prog:      p,
		Important: true,
	}
}

func (mgr *Manager) corpusMinimization() {
	for range time.NewTicker(time.Minute).C {
		mgr.mu.Lock()
		mgr.minimizeCorpusLocked()
		mgr.mu.Unlock()
	}
}

func (mgr *Manager) MaxSignal() signal.Signal {
	if fuzzer := mgr.fuzzer.Load(); fuzzer != nil {
		return fuzzer.Cover.CopyMaxSignal()
	}
	return nil
}

func (mgr *Manager) fuzzerLoop(fuzzerObj *fuzzer.Fuzzer) {
	ctx := context.Background()

	// 创建并启动覆盖率记录器，不管是否使用LLM都会记录覆盖率
	coverageRecorder := NewCoverageRecorder(mgr, *flagLLM)
	go coverageRecorder.Run(ctx)
	log.Logf(0, "覆盖率记录器已启动，将定期记录覆盖率变化")

	// 创建并启动LLM增强器
	if mgr.cfg.Experimental.LLMAPIEnabled && *flagLLM {
		// 仅当同时满足配置启用和命令行参数启用时，才创建LLM增强器
		log.Logf(0, "LLM增强已通过-llm参数和配置启用")
		mgr.llmEnhancer = NewLLMEnhancer(mgr)
		go mgr.llmEnhancer.Run(ctx)
		log.Logf(0, "LLM增强器已启动，将定期对高覆盖率程序进行增强")
	} else if *flagLLM {
		log.Logf(0, "LLM增强器未启动：虽然指定了-llm参数，但配置中未启用LLM API")
	} else if mgr.cfg.Experimental.LLMAPIEnabled {
		log.Logf(0, "LLM增强器未启动：虽然配置中启用了LLM API，但未指定-llm参数")
	}

	for ; ; time.Sleep(time.Second / 2) {
		if mgr.cfg.Cover && !mgr.cfg.Snapshot {
			// Distribute new max signal over all instances.
			newSignal := fuzzerObj.Cover.GrabSignalDelta()
			if len(newSignal) != 0 {
				log.Logf(3, "分发 %d 个新信号", len(newSignal))
				mgr.serv.DistributeSignalDelta(newSignal)
			}
		}

		// Update the state machine.
		if fuzzerObj.CandidateTriageFinished() {
			if mgr.mode == ModeCorpusTriage {
				mgr.exit("corpus triage")
			} else {
				mgr.mu.Lock()
				if mgr.phase == phaseLoadedCorpus {
					if !mgr.cfg.Snapshot {
						mgr.serv.TriagedCorpus()
					}
					if mgr.cfg.HubClient != "" {
						mgr.setPhaseLocked(phaseTriagedCorpus)
						go mgr.hubSyncLoop(pickGetter(mgr.cfg.HubKey),
							fuzzerObj.Config.EnabledCalls)
					} else {
						mgr.setPhaseLocked(phaseTriagedHub)
					}
				} else if mgr.phase == phaseQueriedHub {
					mgr.setPhaseLocked(phaseTriagedHub)
				}
				mgr.mu.Unlock()
			}
		}
	}
}

func (mgr *Manager) setPhaseLocked(newPhase int) {
	if mgr.phase == newPhase {
		panic("repeated phase update")
	}
	if newPhase == phaseTriagedHub {
		// Start reproductions.
		go mgr.reproLoop.Loop(vm.ShutdownCtx())
	}
	mgr.phase = newPhase
}

func (mgr *Manager) needMoreCandidates() bool {
	return mgr.fuzzer.Load().CandidateTriageFinished()
}

func (mgr *Manager) hubIsUnreachable() {
	var dash *dashapi.Dashboard
	mgr.mu.Lock()
	if mgr.phase == phaseTriagedCorpus {
		dash = mgr.dash
		mgr.setPhaseLocked(phaseTriagedHub)
		log.Errorf("did not manage to connect to syz-hub; moving forward")
	}
	mgr.mu.Unlock()
	if dash != nil {
		mgr.dash.LogError(mgr.cfg.Name, "did not manage to connect to syz-hub")
	}
}

// trackUsedFiles() is checking that the files that syz-manager needs are not changed while it's running.
func (mgr *Manager) trackUsedFiles() {
	usedFiles := make(map[string]time.Time) // file name to modification time
	addUsedFile := func(f string) {
		if f == "" {
			return
		}
		stat, err := os.Stat(f)
		if err != nil {
			log.Fatalf("failed to stat %v: %v", f, err)
		}
		usedFiles[f] = stat.ModTime()
	}
	cfg := mgr.cfg
	addUsedFile(cfg.ExecprogBin)
	addUsedFile(cfg.ExecutorBin)
	addUsedFile(cfg.SSHKey)
	if vmlinux := filepath.Join(cfg.KernelObj, mgr.sysTarget.KernelObject); osutil.IsExist(vmlinux) {
		addUsedFile(vmlinux)
	}
	if cfg.Image != "9p" {
		addUsedFile(cfg.Image)
	}
	for range time.NewTicker(30 * time.Second).C {
		for f, mod := range usedFiles {
			stat, err := os.Stat(f)
			if err != nil {
				log.Fatalf("failed to stat %v: %v", f, err)
			}
			if mod != stat.ModTime() {
				log.Fatalf("file %v that syz-manager uses has been modified by an external program\n"+
					"this can lead to arbitrary syz-manager misbehavior\n"+
					"modification time has changed: %v -> %v\n"+
					"don't modify files that syz-manager uses. exiting to prevent harm",
					f, mod, stat.ModTime())
			}
		}
	}
}

func (mgr *Manager) dashboardReporter() {
	webAddr := publicWebAddr(mgr.cfg.HTTP)
	triageInfoSent := false
	var lastFuzzingTime time.Duration
	var lastCrashes, lastSuppressedCrashes, lastExecs uint64
	for range time.NewTicker(time.Minute).C {
		mgr.mu.Lock()
		corpus := mgr.corpus
		mgr.mu.Unlock()
		if corpus == nil {
			continue
		}
		mgr.mu.Lock()
		req := &dashapi.ManagerStatsReq{
			Name:              mgr.cfg.Name,
			Addr:              webAddr,
			UpTime:            time.Duration(mgr.statUptime.Val()) * time.Second,
			Corpus:            uint64(corpus.StatProgs.Val()),
			PCs:               uint64(corpus.StatCover.Val()),
			Cover:             uint64(corpus.StatSignal.Val()),
			CrashTypes:        uint64(mgr.statCrashTypes.Val()),
			FuzzingTime:       time.Duration(mgr.statFuzzingTime.Val()) - lastFuzzingTime,
			Crashes:           uint64(mgr.statCrashes.Val()) - lastCrashes,
			SuppressedCrashes: uint64(mgr.statSuppressed.Val()) - lastSuppressedCrashes,
			Execs:             uint64(mgr.servStats.StatExecs.Val()) - lastExecs,
		}
		if mgr.phase >= phaseTriagedCorpus && !triageInfoSent {
			triageInfoSent = true
			req.TriagedCoverage = uint64(corpus.StatSignal.Val())
			req.TriagedPCs = uint64(corpus.StatCover.Val())
		}
		mgr.mu.Unlock()

		if err := mgr.dash.UploadManagerStats(req); err != nil {
			log.Logf(0, "failed to upload dashboard stats: %v", err)
			continue
		}
		mgr.mu.Lock()
		lastFuzzingTime += req.FuzzingTime
		lastCrashes += req.Crashes
		lastSuppressedCrashes += req.SuppressedCrashes
		lastExecs += req.Execs
		mgr.mu.Unlock()
	}
}

func (mgr *Manager) dashboardReproTasks() {
	for range time.NewTicker(20 * time.Minute).C {
		if !mgr.reproLoop.CanReproMore() {
			// We don't need reproducers at the moment.
			continue
		}
		resp, err := mgr.dash.LogToRepro(&dashapi.LogToReproReq{BuildID: mgr.cfg.Tag})
		if err != nil {
			log.Logf(0, "failed to query logs to reproduce: %v", err)
			continue
		}
		if len(resp.CrashLog) > 0 {
			mgr.externalReproQueue <- &manager.Crash{
				FromDashboard: true,
				Manual:        resp.Type == dashapi.ManualLog,
				Report: &report.Report{
					Title:  resp.Title,
					Output: resp.CrashLog,
				},
			}
		}
	}
}

func (mgr *Manager) CoverageFilter(modules []*vminfo.KernelModule) ([]uint64, error) {
	mgr.reportGenerator.Init(modules)
	filters, err := manager.PrepareCoverageFilters(mgr.reportGenerator, mgr.cfg, true)
	if err != nil {
		return nil, fmt.Errorf("failed to init coverage filter: %w", err)
	}
	mgr.coverFilters = filters
	mgr.http.Cover.Store(&manager.CoverageInfo{
		Modules:         modules,
		ReportGenerator: mgr.reportGenerator,
		CoverFilter:     filters.ExecutorFilter,
	})
	var pcs []uint64
	for pc := range filters.ExecutorFilter {
		pcs = append(pcs, pc)
	}
	return pcs, nil
}

func publicWebAddr(addr string) string {
	if addr == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(addr)
	if err == nil && port != "" {
		if host, err := os.Hostname(); err == nil {
			addr = net.JoinHostPort(host, port)
		}
		if GCE, err := gce.NewContext(""); err == nil {
			addr = net.JoinHostPort(GCE.ExternalIP, port)
		}
	}
	return "http://" + addr
}

func (mgr *Manager) saveSyscallInfo() error {
	// 检查target是否为nil
	if mgr == nil || mgr.target == nil {
		return fmt.Errorf("target未初始化")
	}

	// 获取系统调用信息
	syscalls := mgr.target.Syscalls
	if len(syscalls) == 0 {
		return fmt.Errorf("没有可用的系统调用")
	}

	// 准备保存的信息
	type SyscallInfo struct {
		Name        string   `json:"name"`
		Attrs       []string `json:"attrs,omitempty"`
		Number      uint64   `json:"number"`
		Args        []string `json:"args"`
		ReturnType  string   `json:"return_type"`
		Description string   `json:"description,omitempty"`
	}

	syscallInfos := make([]SyscallInfo, 0, len(syscalls))
	for _, syscall := range syscalls {
		// 检查syscall是否为nil
		if syscall == nil {
			continue
		}

		args := make([]string, 0, len(syscall.Args))
		for _, arg := range syscall.Args {
			if arg.Type != nil {
				args = append(args, fmt.Sprintf("%s %s", arg.Type.Name(), arg.Name))
			} else {
				args = append(args, fmt.Sprintf("unknown %s", arg.Name))
			}
		}

		// 从SyscallAttrs中提取属性
		attrs := extractSyscallAttrs(syscall.Attrs)

		// 检查syscall.Ret是否为nil
		retTypeName := "void"
		if syscall.Ret != nil {
			retTypeName = syscall.Ret.Name()
		}

		info := SyscallInfo{
			Name:       syscall.Name,
			Attrs:      attrs,
			Number:     syscall.NR,
			Args:       args,
			ReturnType: retTypeName,
		}
		syscallInfos = append(syscallInfos, info)
	}

	// 检查Workdir是否存在
	if mgr.cfg == nil || mgr.cfg.Workdir == "" {
		return fmt.Errorf("工作目录未设置")
	}

	// 保存到文件
	outFile := filepath.Join(mgr.cfg.Workdir, "syscalls_info.json")
	data, err := json.MarshalIndent(syscallInfos, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化系统调用信息失败: %v", err)
	}

	err = os.WriteFile(outFile, data, 0644)
	if err != nil {
		return fmt.Errorf("保存系统调用信息到文件失败: %v", err)
	}

	log.Logf(0, "已将 %d 个系统调用信息保存到 %s", len(syscallInfos), outFile)
	return nil
}

// 从SyscallAttrs中提取所有非默认值的属性作为字符串列表
func extractSyscallAttrs(attrs prog.SyscallAttrs) []string {
	var result []string

	if attrs.Disabled {
		result = append(result, "disabled")
	}
	if attrs.Timeout > 0 {
		result = append(result, fmt.Sprintf("timeout:%d", attrs.Timeout))
	}
	if attrs.ProgTimeout > 0 {
		result = append(result, fmt.Sprintf("prog_timeout:%d", attrs.ProgTimeout))
	}
	if attrs.IgnoreReturn {
		result = append(result, "ignore_return")
	}
	if attrs.BreaksReturns {
		result = append(result, "breaks_returns")
	}
	if attrs.NoGenerate {
		result = append(result, "no_generate")
	}
	if attrs.NoMinimize {
		result = append(result, "no_minimize")
	}
	if attrs.RemoteCover {
		result = append(result, "remote_cover")
	}
	if attrs.Automatic {
		result = append(result, "automatic")
	}
	if attrs.AutomaticHelper {
		result = append(result, "automatic_helper")
	}
	if attrs.Fsck != "" {
		result = append(result, fmt.Sprintf("fsck:%s", attrs.Fsck))
	}

	return result
}

// LLMEnhancer 负责使用LLM增强corpus中的程序
type LLMEnhancer struct {
	mgr             *Manager
	lastEnhanceTime time.Time
	enhanceInterval time.Duration // 增强间隔时间
	mu              sync.Mutex

	// 增加记录功能
	statsFile      *os.File  // 统计数据文件
	successFile    *os.File  // 成功序列对文件
	startTime      time.Time // 开始运行时间
	lastCoverage   int       // 上次记录的覆盖率
	covChangeTimes int       // 覆盖率变化次数
}

// SequencePair 记录一对原始和增强后的程序序列
type SequencePair struct {
	Timestamp       string `json:"timestamp"`
	CoverageBefore  int    `json:"coverage_before"`
	CoverageAfter   int    `json:"coverage_after"`
	CoverageGain    int    `json:"coverage_gain"`
	OriginalProgram string `json:"original_program"`
	EnhancedProgram string `json:"enhanced_program"`
	OriginalHash    string `json:"original_hash"`
	EnhancedHash    string `json:"enhanced_hash"`
}

type CoverageRecorder struct {
	mgr            *Manager
	mu             sync.Mutex
	statsFile      *os.File  // 统计数据文件
	startTime      time.Time // 开始运行时间
	lastCoverage   int       // 上次记录的覆盖率
	covChangeTimes int       // 覆盖率变化次数
}

// 创建新的覆盖率记录器
func NewCoverageRecorder(mgr *Manager, useLLM bool) *CoverageRecorder {
	// 创建统计文件目录
	statsDir := filepath.Join(mgr.cfg.Workdir, "coverage_stats")
	os.MkdirAll(statsDir, 0755)

	// 创建文件名，包含时间戳和模式标记
	timeStr := time.Now().Format("2006-01-02_15-04-05")
	modeTag := "normal"
	if useLLM {
		modeTag = "llm"
	}
	statsFilePath := filepath.Join(statsDir, fmt.Sprintf("coverage_stats_%s_%s.csv", modeTag, timeStr))

	// 创建并打开统计文件
	statsFile, err := os.Create(statsFilePath)
	if err != nil {
		log.Errorf("无法创建覆盖率统计文件: %v", err)
	} else {
		// 写入CSV头
		statsFile.WriteString("timestamp,seconds_elapsed,coverage,corpus_size,cov_change_times\n")
		log.Logf(0, "已创建覆盖率统计文件 (%s模式): %s", modeTag, statsFilePath)
	}

	startTime := time.Now()

	return &CoverageRecorder{
		mgr:            mgr,
		statsFile:      statsFile,
		startTime:      startTime,
		lastCoverage:   0,
		covChangeTimes: 0,
	}
}

// 运行覆盖率记录循环
func (cr *CoverageRecorder) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			cr.Close()
			return
		case <-ticker.C:
			cr.recordCurrentCoverage()
		}
	}
}

// 关闭文件
func (cr *CoverageRecorder) Close() {
	if cr.statsFile != nil {
		cr.statsFile.Close()
		cr.statsFile = nil
	}
}

// 记录当前覆盖率
func (cr *CoverageRecorder) recordCurrentCoverage() {
	if cr.statsFile == nil {
		return
	}

	cr.mu.Lock()
	defer cr.mu.Unlock()

	fuzzerObj := cr.mgr.fuzzer.Load()
	if fuzzerObj == nil {
		return
	}

	var corpusSize int
	var currentCoverage int

	// 获取当前覆盖率
	if fuzzerObj.Cover != nil {
		currentCoverage = fuzzerObj.Cover.Count()
	}

	// 获取Corpus大小
	if cr.mgr.corpus != nil {
		corpusSize = cr.mgr.corpus.StatProgs.Val()
	}

	// 检查覆盖率是否变化
	if currentCoverage != cr.lastCoverage {
		cr.covChangeTimes++
		cr.lastCoverage = currentCoverage
	}

	// 计算经过的秒数
	secondsElapsed := int(time.Since(cr.startTime).Seconds())

	// 写入统计数据
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	statsLine := fmt.Sprintf("%s,%d,%d,%d,%d\n",
		timestamp, secondsElapsed, currentCoverage, corpusSize, cr.covChangeTimes)

	cr.statsFile.WriteString(statsLine)
	cr.statsFile.Sync()
}

// 创建新的LLM增强器
func NewLLMEnhancer(mgr *Manager) *LLMEnhancer {
	// 创建统计文件目录
	statsDir := filepath.Join(mgr.cfg.Workdir, "llm_stats")
	os.MkdirAll(statsDir, 0755)

	// 创建文件名，包含时间戳和llm标记
	timeStr := time.Now().Format("2006-01-02_15-04-05")
	statsFilePath := filepath.Join(statsDir, fmt.Sprintf("coverage_stats_llm_%s.csv", timeStr))
	successFilePath := filepath.Join(statsDir, fmt.Sprintf("success_sequences_llm_%s.jsonl", timeStr))

	// 创建并打开统计文件
	statsFile, err := os.Create(statsFilePath)
	if err != nil {
		log.Errorf("无法创建LLM统计文件: %v", err)
	} else {
		// 写入CSV头
		statsFile.WriteString("timestamp,seconds_elapsed,coverage,corpus_size,cov_change_times\n")
	}

	// 创建并打开成功序列文件
	successFile, err := os.Create(successFilePath)
	if err != nil {
		log.Errorf("无法创建LLM成功序列文件: %v", err)
	} else {
		// JSONL格式不需要特殊的文件头
		log.Logf(0, "已创建系统调用序列记录文件 (JSONL格式): %s", successFilePath)
	}

	startTime := time.Now()

	// 设置初始增强间隔为10秒，更快开始第一次后的增强
	enhanceInterval := 10 * time.Second
	log.Logf(0, "【调试】创建LLM增强器，初始增强间隔为%v", enhanceInterval)

	return &LLMEnhancer{
		mgr:             mgr,
		lastEnhanceTime: time.Now(),
		enhanceInterval: enhanceInterval,
		statsFile:       statsFile,
		successFile:     successFile,
		startTime:       startTime,
		lastCoverage:    0,
		covChangeTimes:  0,
	}
}

// 运行LLM增强循环
func (le *LLMEnhancer) Run(ctx context.Context) {
	// 定期重启，防止因单次panic停止整个增强过程
	defer func() {
		if r := recover(); r != nil {
			log.Logf(0, "【严重错误】LLM增强器运行时发生panic: %v，将在5秒后重启", r)
			debug.PrintStack() // 打印堆栈跟踪以便调试
			time.Sleep(5 * time.Second)
			go le.Run(ctx) // 重新启动增强器
		}
	}()

	// 添加健康检查
	healthTicker := time.NewTicker(1 * time.Minute) // 降低到1分钟
	defer healthTicker.Stop()

	// 原有代码
	go le.recordCoverageStats()

	log.Logf(0, "【调试】LLM增强循环开始运行，使用%v的增强间隔", le.enhanceInterval)

	enhanceCount := 0
	lastTickTime := time.Now()

	for {
		now := time.Now()
		log.Logf(3, "【循环跟踪】LLM增强器循环迭代，距上次: %v", now.Sub(lastTickTime))
		lastTickTime = now

		select {
		case <-ctx.Done():
			log.Logf(0, "【调试】LLM增强器收到终止信号，即将关闭")
			le.closeFiles()
			return

		case <-healthTicker.C:
			// 定期健康检查
			log.Logf(0, "【健康】LLM增强器健康检查：已运行%d次增强", enhanceCount)
			// 强制记录一次当前状态
			le.mu.Lock()
			lastTime := le.lastEnhanceTime
			interval := le.enhanceInterval
			le.mu.Unlock()
			timeNow := time.Now()
			timeElapsed := timeNow.Sub(lastTime)
			log.Logf(0, "【健康】上次增强时间: %v, 当前时间: %v, 已过时间: %v, 需要间隔: %v",
				lastTime.Format("15:04:05.000"), timeNow.Format("15:04:05.000"),
				timeElapsed, interval)

		case <-time.After(5 * time.Second): // 每5秒检查一次
			// 用匿名函数包装增强操作，使panic不会导致整个循环终止
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Logf(0, "【警告】enhanceWithLLM发生panic: %v", r)
						debug.PrintStack() // 打印堆栈跟踪以便调试
					}
				}()

				log.Logf(1, "【调试】尝试运行LLM增强操作...")
				le.enhanceWithLLM()
				enhanceCount++
			}()
		}
	}
}

// 关闭文件
func (le *LLMEnhancer) closeFiles() {
	if le.statsFile != nil {
		le.statsFile.Close()
		le.statsFile = nil
	}
	if le.successFile != nil {
		le.successFile.Close()
		le.successFile = nil
	}
}

// 定期记录覆盖率统计信息
func (le *LLMEnhancer) recordCoverageStats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		le.recordCurrentCoverage()
	}
}

// 记录当前覆盖率
func (le *LLMEnhancer) recordCurrentCoverage() {
	if le.statsFile == nil {
		return
	}

	le.mu.Lock()
	defer le.mu.Unlock()

	fuzzerObj := le.mgr.fuzzer.Load()
	if fuzzerObj == nil {
		return
	}

	var corpusSize int
	var currentCoverage int

	// 获取当前覆盖率
	if fuzzerObj.Cover != nil {
		currentCoverage = fuzzerObj.Cover.Count()
	}

	// 获取Corpus大小
	if le.mgr.corpus != nil {
		corpusSize = le.mgr.corpus.StatProgs.Val()
	}

	// 检查覆盖率是否变化
	if currentCoverage != le.lastCoverage {
		le.covChangeTimes++
		le.lastCoverage = currentCoverage
	}

	// 计算经过的秒数
	secondsElapsed := int(time.Since(le.startTime).Seconds())

	// 写入统计数据
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	statsLine := fmt.Sprintf("%s,%d,%d,%d,%d\n",
		timestamp, secondsElapsed, currentCoverage, corpusSize, le.covChangeTimes)

	le.statsFile.WriteString(statsLine)
	le.statsFile.Sync()
}

// 记录成功的序列对
func (le *LLMEnhancer) recordSuccessSequence(originalProg, enhancedProg *prog.Prog, coverageBefore, coverageAfter int) {
	if le.successFile == nil {
		log.Errorf("【错误】无法记录成功序列：序列保存文件为nil")
		return
	}

	le.mu.Lock()
	defer le.mu.Unlock()

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	log.Logf(0, "【调试】开始记录成功序列，时间戳: %s", timestamp)

	// 格式化原始和增强后的程序
	originalStr := originalProg.String()
	enhancedStr := enhancedProg.String()

	// 记录程序长度，便于调试
	log.Logf(0, "【调试】原始程序长度: %d, 增强程序长度: %d",
		len(originalStr), len(enhancedStr))

	// 计算哈希（可选）
	originalHash := fmt.Sprintf("%x", sha1.Sum([]byte(originalStr)))
	enhancedHash := fmt.Sprintf("%x", sha1.Sum([]byte(enhancedStr)))

	log.Logf(0, "【调试】原始哈希: %s, 增强哈希: %s",
		originalHash, enhancedHash)

	record := SequencePair{
		Timestamp:       timestamp,
		CoverageBefore:  coverageBefore,
		CoverageAfter:   coverageAfter,
		CoverageGain:    coverageAfter - coverageBefore,
		OriginalProgram: originalStr,
		EnhancedProgram: enhancedStr,
		OriginalHash:    originalHash,
		EnhancedHash:    enhancedHash,
	}

	// 将JSON对象序列化为一行
	jsonData, err := json.Marshal(record)
	if err != nil {
		log.Errorf("【错误】序列化JSON失败: %v", err)
		return
	}

	log.Logf(0, "【调试】JSON数据长度: %d字节", len(jsonData))

	// 写入JSONL格式（每行一个JSON对象）
	bytesWritten, err := le.successFile.Write(jsonData)
	if err != nil {
		log.Errorf("【错误】写入JSONL数据失败: %v", err)
		return
	}

	// 写入换行符
	_, err = le.successFile.WriteString("\n")
	if err != nil {
		log.Errorf("【错误】写入换行符失败: %v", err)
		return
	}

	// 确保写入磁盘
	err = le.successFile.Sync()
	if err != nil {
		log.Errorf("【错误】同步文件到磁盘失败: %v", err)
		return
	}

	log.Logf(0, "【调试】成功写入序列对数据：%d字节, 覆盖率: %d -> %d (+%d)",
		bytesWritten, coverageBefore, coverageAfter, coverageAfter-coverageBefore)

	// 检查文件大小以确保数据被写入
	fileInfo, err := le.successFile.Stat()
	if err != nil {
		log.Errorf("【错误】获取文件状态失败: %v", err)
	} else {
		log.Logf(0, "【调试】当前序列文件大小: %d字节", fileInfo.Size())
	}
}

// 格式化程序调用序列（带详细信息）
func formatProgCallsWithDetails(p *prog.Prog) string {
	if p == nil {
		return "nil"
	}

	return p.String()
}

// 使用LLM进行增强
func (le *LLMEnhancer) enhanceWithLLM() {
	le.mu.Lock()
	timeSinceLast := time.Since(le.lastEnhanceTime)
	log.Logf(0, "【增强检查】当前时间: %v, 上次增强时间: %v, 已过时间: %v, 需要间隔: %v",
		time.Now().Format("15:04:05.000"),
		le.lastEnhanceTime.Format("15:04:05.000"),
		timeSinceLast, le.enhanceInterval)

	if timeSinceLast < le.enhanceInterval {
		log.Logf(0, "【调试】LLM增强器间隔未到，跳过本次增强 (已过时间: %v, 需要间隔: %v)", timeSinceLast, le.enhanceInterval)
		le.mu.Unlock()
		return
	}
	log.Logf(0, "【调试】LLM增强器间隔已到，准备开始新的增强 (已过时间: %v > 间隔: %v)", timeSinceLast, le.enhanceInterval)

	// 先更新时间戳，防止重复启动增强（在增强过程中发生其他操作时）
	le.lastEnhanceTime = time.Now()
	le.mu.Unlock()

	log.Logf(0, "【调试】开始LLM增强，API URL: %s", le.mgr.cfg.LLM)
	log.Logf(0, "【调试】LLM配置: UseOpenAIFormat=%v", le.mgr.cfg.EnabledCalls != nil)

	// 测试API连接
	apiURL := le.mgr.cfg.LLM
	if err := testLLMAPIAvailability(apiURL); err != nil {
		log.Logf(0, "【错误】LLM API连接失败: %v", err)
		return
	}
	log.Logf(0, "【调试】LLM API连接测试成功")

	// 获取语料库
	le.mgr.mu.Lock()
	fuzzerObj := le.mgr.fuzzer.Load()
	le.mgr.mu.Unlock()

	if fuzzerObj == nil {
		log.Logf(0, "【错误】无法获取fuzzer实例")
		return
	}

	items := le.mgr.getMinimizedCorpus()
	if len(items) == 0 {
		log.Logf(0, "【警告】LLM增强：没有可用的语料库程序")
		return
	}
	log.Logf(0, "【调试】Corpus大小: %d", len(items))

	// 获取当前覆盖率基线
	coverageBefore := 0
	if fuzzerObj.Cover != nil {
		coverageBefore = fuzzerObj.Cover.Count()
	}
	log.Logf(0, "【调试】当前覆盖率基线: %d", coverageBefore)

	// 最多尝试5个程序进行增强
	maxTries := 5
	for i := 0; i < maxTries; i++ {
		// 随机选择一个程序
		if len(items) == 0 {
			log.Logf(0, "【警告】没有可用的程序进行增强")
			return
		}

		randIndex := rand.Intn(len(items))
		prog := items[randIndex].Prog

		// 检查程序大小
		if len(prog.Calls) < 1 || len(prog.Calls) > 20 {
			log.Logf(0, "【调试】跳过程序 #%d: 调用数量不适合 (%d)", randIndex, len(prog.Calls))
			continue
		}

		// 检查程序的信号
		signalSize := len(items[randIndex].Signal)
		log.Logf(0, "【调试】尝试 #%d: 选择的程序 #%d, 信号数: %d", i+1, randIndex, signalSize)

		// 输出程序详情
		log.Logf(0, "【调试】选择的程序内容: %s", prog.String())

		// 计算程序哈希
		originalHash := fmt.Sprintf("%x", sha1.Sum([]byte(prog.Serialize())))
		log.Logf(0, "【调试】原始程序哈希: %s", originalHash)

		// 使用LLM增强程序
		startTime := time.Now()
		enhancedProg, err := fuzzerObj.UseLLMForMutation(prog.Clone())
		callDuration := time.Since(startTime)

		if err != nil {
			log.Logf(0, "【错误】LLM增强调用失败 (耗时: %v): %v", callDuration, err)
			continue
		}

		if enhancedProg == nil {
			log.Logf(0, "【错误】LLM返回了空程序 (耗时: %v)", callDuration)
			continue
		}

		// 校验增强后的程序
		enhancedHash := fmt.Sprintf("%x", sha1.Sum([]byte(enhancedProg.Serialize())))
		log.Logf(0, "【调试】增强后程序哈希: %s", enhancedHash)

		if originalHash == enhancedHash {
			log.Logf(0, "【警告】LLM未对程序做出任何改变，哈希相同")
			continue
		}

		log.Logf(0, "【成功】LLM成功变异程序 (耗时: %v)", callDuration)
		log.Logf(0, "【调试】原始程序: %s", prog.String())
		log.Logf(0, "【调试】增强程序: %s", enhancedProg.String())

		// 添加到候选队列
		candidates := []fuzzer.Candidate{
			{
				Prog:  enhancedProg,
				Flags: 0,
			},
		}

		fuzzerObj.AddCandidates(candidates)
		log.Logf(0, "【调试】已将LLM增强后的程序添加到候选队列")

		// 等待覆盖率更新
		log.Logf(0, "【调试】等待5秒钟让覆盖率更新...")
		time.Sleep(5 * time.Second)

		// 获取增强后的覆盖率
		coverageAfter := 0
		if fuzzerObj.Cover != nil {
			coverageAfter = fuzzerObj.Cover.Count()
		}

		log.Logf(0, "【调试】覆盖率检查: 之前=%d, 之后=%d, 差异=%d",
			coverageBefore, coverageAfter, coverageAfter-coverageBefore)

		// 如果覆盖率有提升，记录成功序列
		if coverageAfter > coverageBefore {
			log.Logf(0, "【成功】检测到覆盖率提升: %d -> %d (+%d)",
				coverageBefore, coverageAfter, coverageAfter-coverageBefore)

			// 确保记录文件存在
			if le.successFile == nil {
				statsDir := filepath.Join(le.mgr.cfg.Workdir, "llm_stats")
				os.MkdirAll(statsDir, 0755)
				timeStr := time.Now().Format("2006-01-02_15-04-05")
				successFilePath := filepath.Join(statsDir, fmt.Sprintf("success_sequences_%s.jsonl", timeStr))
				newFile, err := os.Create(successFilePath)
				if err != nil {
					log.Logf(0, "【错误】无法创建序列文件: %v", err)
				} else {
					le.successFile = newFile
					log.Logf(0, "【调试】已创建新的序列记录文件: %s", successFilePath)
				}
			}

			le.recordSuccessSequence(prog, enhancedProg, coverageBefore, coverageAfter)
		}

		// 找到了有效变异，退出循环
		break
	}

	log.Logf(0, "【调试】LLM增强操作完成，下次增强将在%v后进行", le.enhanceInterval)
}

// 添加LLM API可用性测试函数
func testLLMAPIAvailability(apiURL string) error {
	if apiURL == "" {
		apiURL = "http://100.64.88.112:5231"
	}

	// 构建一个简单的测试请求
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
		{Role: "system", Content: "你好"},
		{Role: "user", Content: "测试消息"},
	}

	reqBody := OpenAIRequest{
		Model:     "gpt-3.5-turbo",
		Messages:  messages,
		MaxTokens: 10,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("序列化测试请求失败: %w", err)
	}

	// 设置5秒超时
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	log.Logf(0, "正在测试LLM API: %s", apiURL)
	resp, err := client.Post(apiURL+"/v1/chat/completions", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("连接LLM API失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API返回非200状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	return nil
}
