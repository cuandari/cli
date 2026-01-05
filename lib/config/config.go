package config

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

type EXECUTION_MODE int32

const (
	EXECUTION_MODE_TRACE EXECUTION_MODE = iota
	EXECUTION_MODE_RUN   EXECUTION_MODE = iota + 1
)

type SyscallConfig struct {
	SyscallsAllowList              []string `split_words:"true"`
	SyscallsKillTargetIfNotAllowed bool     `split_words:"true" default:"true"`
	SyscallsDenyTargetIfNotAllowed bool     `split_words:"true" default:"false"`
	// Syscall category toggles: when true, the library should include
	// the corresponding syscall group in the allow policy.
	SyscallsAllowProcessManagement         bool `split_words:"true" default:"false"`
	SyscallsAllowMemoryManagement          bool `split_words:"true" default:"false"`
	SyscallsAllowProcessSynchronization    bool `split_words:"true" default:"false"`
	SyscallsAllowSignals                   bool `split_words:"true" default:"false"`
	SyscallsAllowBasicTime                 bool `split_words:"true" default:"false"`
	SyscallsAllowMisc                      bool `split_words:"true" default:"false"`
	SyscallsAllowSecurityAndPermissions    bool `split_words:"true" default:"false"`
	SyscallsAllowSystemInformation         bool `split_words:"true" default:"false"`
	SyscallsAllowProcessCommunication      bool `split_words:"true" default:"false"`
	SyscallsAllowTimersAndClocksManagement bool `split_words:"true" default:"false"`
}

type FsConfig struct {
	FileSystemAllowRead        bool `split_words:"true" default:"false"`
	FileSystemAllowWrite       bool `split_words:"true" default:"false"`
	FileSystemAllowPermissions bool `split_words:"true" default:"false"`
}

type NetworkConfig struct {
	NetworkAllowClient bool `split_words:"true" default:"false"`
	NetworkAllowServer bool `split_words:"true" default:"false"`
	LocalSocketsAllow  bool `split_words:"true" default:"false"`
}

type ProcessConfig struct {
	ProcessAllowManagement bool `split_words:"true" default:"false"`
}

// TargetConfig defines the executable and arguments of the process to start.
type TargetConfig struct {
	// TargetBinary is the absolute or PATH-resolved binary to execute.
	TargetBinary string `split_words:"true" default:""`
	// TargetArgs holds the arguments to pass to the target binary.
	TargetArgs []string `split_words:"true"`
}

type GatekeeperConfig struct {
	EnforceOnStartup       bool           `split_words:"true" default:"true"`
	ExecutionMode          EXECUTION_MODE `env:"EXECUTION_MODE,enum=TRACE,RUN"`
	TriggerEnforceLogMatch string         `split_words:"true" default:""`
	TriggerEnforceSignal   string         `split_words:"true" default:""`
	VerboseLog             bool           `split_words:"true" default:"false"`
}

type Config struct {
	FsConfig
	GatekeeperConfig
	NetworkConfig
	ProcessConfig
	TargetConfig
	SyscallConfig
}

var globalConfig *Config

func Load() {
	var config Config
	err := envconfig.Process("CUANDARI", &config)
	if err != nil {
		panic(fmt.Sprintf("unable to read environment configuration %s", err.Error()))
	}

	globalConfig = &config
}

func Get() *Config {
	if globalConfig == nil {
		Load()
	}

	return globalConfig
}

// Reset clears the global configuration. Useful for tests to ensure a fresh
// configuration between cases.
func Reset() {
	globalConfig = nil
}
