package main

import (
	"os"
	"testing"

	config "github.com/cuandari/cli/lib/config"
	"github.com/stretchr/testify/assert"
)

func TestNoImplicitAllow(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-implicit-commands=false"}

	configureAndParseArgs()
	a.Empty(config.Get().SyscallsAllowList)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowFileSystemReadAccess(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-file-system-read", "ls", "-l"}

	configureAndParseArgs()
	a.True(config.Get().FileSystemAllowRead)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowFileSystemWriteAccess(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-file-system-write", "ls", "-l"}

	configureAndParseArgs()
	a.True(config.Get().FileSystemAllowWrite)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowFileSystemAccess(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-file-system", "ls", "-l"}

	configureAndParseArgs()
	a.True(config.Get().FileSystemAllowWrite)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowProcessManagement(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-process-management", "ps", "-ef"}

	configureAndParseArgs()
	a.True(config.Get().SyscallsAllowProcessManagement)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowNetworkClient(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-network-client", "curl", "https://google.com"}

	configureAndParseArgs()
	a.True(config.Get().NetworkAllowClient)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowNetworkServer(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-network-server", "binary"}

	configureAndParseArgs()
	a.True(config.Get().NetworkAllowServer)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowNetworking(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-networking", "curl", "https://google.com"}

	configureAndParseArgs()
	a.True(config.Get().NetworkAllowServer)
	a.True(config.Get().NetworkAllowClient)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowMemoryManagement(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-memory-management", "binary"}

	configureAndParseArgs()
	a.True(config.Get().SyscallsAllowMemoryManagement)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowSignals(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-signals", "binary"}

	configureAndParseArgs()
	a.True(config.Get().SyscallsAllowSignals)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowTimersAndClocksManagement(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-timers-and-clocks-management", "binary"}

	configureAndParseArgs()
	a.True(config.Get().SyscallsAllowTimersAndClocksManagement)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowSecurityAndPermissions(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-security-and-permissions", "binary"}

	configureAndParseArgs()
	a.True(config.Get().SyscallsAllowSecurityAndPermissions)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowSystemInformation(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-system-information", "binary"}
	configureAndParseArgs()
	a.True(config.Get().SyscallsAllowSystemInformation)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowProcessCommunication(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-process-communication", "binary"}

	configureAndParseArgs()
	a.True(config.Get().SyscallsAllowProcessCommunication)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowProcessSynchronization(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-process-synchronization", "binary"}

	configureAndParseArgs()
	a.True(config.Get().SyscallsAllowProcessSynchronization)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestAllowMisc(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--allow-misc", "binary"}

	configureAndParseArgs()
	a.True(config.Get().SyscallsAllowMisc)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestEnorceAfterLogMatch(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--enforce-on-startup=false", "--trigger-enforce-on-log-match", "test", "binary"}

	configureAndParseArgs()
	a.False(config.Get().EnforceOnStartup)
	a.Equal("test", config.Get().TriggerEnforceLogMatch)
}

func TestEnforceAfterSignal(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--enforce-on-startup=false", "--trigger-enforce-on-signal", "SIGUSR1", "binary"}

	configureAndParseArgs()
	a.False(config.Get().EnforceOnStartup)
	a.Equal(config.Get().TriggerEnforceSignal, "SIGUSR1")
}

func TestEnforceOnStartup(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "binary"}

	configureAndParseArgs()
	a.True(config.Get().EnforceOnStartup)
}

func TestEnforceStartupMissingTrigger(t *testing.T) {
	a := assert.New(t)
	config.Reset()

	// Intercept osExit to capture the exit code without exiting the test process
	origExit := osExit
	defer func() { osExit = origExit }()
	exited := 0
	osExit = func(code int) { exited = code; panic("exit") }

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected configureAndParseArgs to exit")
		}
		a.Equal(100, exited)
	}()

	os.Args = []string{"", "run", "--enforce-on-startup=false", "binary"}
	configureAndParseArgs()
}

func TestTriggerEnforceLogMatchKillTarget(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--enforce-on-startup=false", "--trigger-enforce-on-log-match", "test", "binary"}

	configureAndParseArgs()
	a.Equal("test", config.Get().TriggerEnforceLogMatch)
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
}

func TestDenyTarget(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--on-syscall-denied", "error", "binary"}

	configureAndParseArgs()
	a.False(config.Get().SyscallsKillTargetIfNotAllowed)
	a.True(config.Get().SyscallsDenyTargetIfNotAllowed)
}

func TestKillTarget(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--on-syscall-denied", "kill", "binary"}

	configureAndParseArgs()
	a.True(config.Get().SyscallsKillTargetIfNotAllowed)
	a.False(config.Get().SyscallsDenyTargetIfNotAllowed)
}

func TestVerboseLog(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "--verbose", "binary"}

	configureAndParseArgs()
	a.True(config.Get().VerboseLog)
}

func TestRunMode(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "run", "binary"}

	configureAndParseArgs()
	a.Equal(config.EXECUTION_MODE_RUN, config.Get().ExecutionMode)
}

func TestTraceMode(t *testing.T) {
	a := assert.New(t)
	config.Reset()
	os.Args = []string{"", "trace", "binary"}

	configureAndParseArgs()
	a.Equal(config.EXECUTION_MODE_TRACE, config.Get().ExecutionMode)
}
