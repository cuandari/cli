// Package main is the entry point for the k6 CLI application. It assembles all the crucial components for the running.
package main

import (
	"context"
	"fmt"
	"os"

	cli "github.com/cuandari/cli/lib/cli"
	"github.com/cuandari/cli/lib/config"
)

var osExit = os.Exit // Assign exit to a variable to allow mocking in unit tests
func exit(code int) {
	osExit(code)
}

// CLI flag type and constants moved to cli package.

func main() {
	mainCtx, _ := context.WithCancel(context.Background())
	// println(fmt.Sprintf("gatekeeper started with %#+v", os.Args))

	conf := configureAndParseArgs()
	_ = startTracee(mainCtx, conf)
	// waitForShutdown(cancel, tracee)
}

func startTracee(c context.Context, conf *config.Config) context.Context {
	program := conf.TargetBinary
	programArgs := conf.TargetArgs
	println(fmt.Sprintf("starting %s with args %#+v", program, programArgs))

	return context.Background()
}

func configureAndParseArgs() *config.Config {
	conf := config.Get()
	cmd := cli.NewCommand()

	if len(os.Args) < 3 {
		fmt.Println("Error: You did not provide enough parameters and flags.")
		cmd.Usage()
		exit(100)
	}

	mode := os.Args[1]

	// Pre-scan for dynamic syscall allow flags and filter them out before parsing
	// Supported forms:
	//  - --allow-syscall-<name>
	//  - --allow-syscall=<name>
	rawArgs := os.Args[2:]
	filteredArgs, dynamicSyscalls := cmd.PreScanDynamicSyscalls(rawArgs)

	// parse known flags now
	err := cmd.Parse(filteredArgs)
	if err != nil {
		fmt.Println(err.Error())
		cmd.Usage()
		exit(100)
	}

	// Build configuration from parsed flags
	conf.FileSystemAllowWrite = *cmd.AllowFileSystemWriteAccess || *cmd.AllowFileSystemAccess
	conf.FileSystemAllowRead = *cmd.AllowFileSystemReadAccess || *cmd.AllowFileSystemWriteAccess || *cmd.AllowFileSystemAccess
	conf.FileSystemAllowPermissions = *cmd.AllowFileSystemPermissionsAccess
	conf.ProcessAllowManagement = *cmd.AllowProcessManagement

	conf.NetworkAllowClient = *cmd.AllowNetworking || (*cmd.AllowNetworkClient && !*cmd.AllowNetworkServer)
	conf.NetworkAllowServer = *cmd.AllowNetworking || *cmd.AllowNetworkServer
	conf.LocalSocketsAllow = *cmd.AllowNetworkLocalSockets

	addImplicitConfiguration := *cmd.AllowImplicitCommands
	conf.SyscallsAllowProcessManagement = addImplicitConfiguration
	conf.SyscallsAllowMemoryManagement = *cmd.AllowMemoryManagement || addImplicitConfiguration
	conf.SyscallsAllowProcessSynchronization = *cmd.AllowProcessSynchronization || addImplicitConfiguration
	conf.SyscallsAllowSignals = *cmd.AllowSignals || addImplicitConfiguration
	conf.SyscallsAllowBasicTime = addImplicitConfiguration
	conf.SyscallsAllowMisc = *cmd.AllowMisc || addImplicitConfiguration
	conf.SyscallsAllowSecurityAndPermissions = *cmd.AllowSecurityAndPermissions || addImplicitConfiguration
	conf.SyscallsAllowSystemInformation = *cmd.AllowSystemInformation || addImplicitConfiguration
	conf.SyscallsAllowProcessCommunication = *cmd.AllowProcessCommunication
	conf.SyscallsAllowTimersAndClocksManagement = *cmd.AllowTimersAndClocksManagement

	// Append dynamically allowed syscalls collected from CLI directly into config
	conf.SyscallsAllowList = append(conf.SyscallsAllowList, dynamicSyscalls...)

	conf.VerboseLog = *cmd.Verbose

	conf.EnforceOnStartup = *cmd.EnforceOnStartup

	if !*cmd.EnforceOnStartup {
		fmt.Println("triggering on ", *cmd.TriggerEnforceOnLogMatch, *cmd.TriggerEnforceOnSignal)
		if *cmd.TriggerEnforceOnLogMatch == "" && *cmd.TriggerEnforceOnSignal == "" {
			fmt.Println("Error: To delay the enforcement of seccomp policies, please also specify either --trigger-enforce-on-log-match or --trigger-enforce-on-signal.")
			cmd.Usage()
			exit(100)
		} else {
			conf.TriggerEnforceLogMatch = *cmd.TriggerEnforceOnLogMatch
			conf.TriggerEnforceSignal = *cmd.TriggerEnforceOnSignal
		}
	}

	conf.TriggerEnforceLogMatch = *cmd.TriggerEnforceOnLogMatch
	conf.TriggerEnforceSignal = *cmd.TriggerEnforceOnSignal

	conf.SyscallsKillTargetIfNotAllowed = cmd.Action != cli.ErrorAction
	conf.SyscallsDenyTargetIfNotAllowed = cmd.Action == cli.ErrorAction

	switch mode {
	case "trace":
		conf.ExecutionMode = config.EXECUTION_MODE_TRACE
	case "run":
		conf.ExecutionMode = config.EXECUTION_MODE_RUN
	default:
		cmd.Usage()
		exit(100)
	}

	// Set target binary and args from remaining CLI args
	trailing := cmd.Args()
	if len(trailing) > 0 {
		conf.TargetBinary = trailing[0]
		if len(trailing) > 1 {
			conf.TargetArgs = trailing[1:]
		}
	}

	return conf
}

// func waitForShutdown(cancel context.CancelFunc, tracee context.Context) {
// 	signal, stop := signal.NotifyContext(context.Background(), syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM)

// 	select {
// 	case <-signal.Done():
// 		println("Received signal from outside")
// 		break
// 	case <-tracee.Done():
// 		println("Tracee got cancelled")
// 		break
// 	}

// 	cancel()
// 	time.Sleep(1 * time.Second)

// 	stop()
// 	<-tracee.Done()

// 	// collect exit code of tracee
// 	traceeCancelCause := context.Cause(tracee)
// 	e := &uroot.ExitEventError{}
// 	errors.As(traceeCancelCause, &e)

// 	exitCode := 0
// 	if e.Signal != "" {
// 		exitCode = 111
// 	} else if e.ExitCode != 0 {
// 		exitCode = e.ExitCode
// 	}

// 	println(fmt.Sprintf("Exiting with code %d", exitCode))
// 	// exit
// 	exit(exitCode)
// }
