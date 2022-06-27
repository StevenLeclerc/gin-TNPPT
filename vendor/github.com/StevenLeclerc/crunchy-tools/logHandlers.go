package crunchyTools

import (
	"github.com/mgutz/ansi"
	"log"
	"os"
)

type logConfig struct {
	LogType     string
	LogPrefix   string
	LogColor    string
	LogPathFile string
	LogFormat   int
	LogOut      *os.File
	Logger      *log.Logger
}

type LogType struct {
	Info *log.Logger
	Warn *log.Logger
	Err  *log.Logger
}

type logImproved interface {
}

var loggersConfigs []logConfig
var loggers LogType

func init() {
	infoLogger := logConfig{
		LogType:     "Info",
		LogPrefix:   "[INFO]",
		LogColor:    "green",
		LogPathFile: "info.log",
		LogFormat:   log.Ldate | log.Lmicroseconds,
		LogOut:      os.Stdout,
	}
	warningLogger := logConfig{
		LogType:     "Warning",
		LogPrefix:   "[WARN]",
		LogColor:    "yellow",
		LogPathFile: "warn.log",
		LogFormat:   log.Ldate | log.Lmicroseconds,
		LogOut:      os.Stdout,
	}
	errorLogger := logConfig{
		LogType:     "Error",
		LogPrefix:   "[ERR]",
		LogColor:    "red",
		LogPathFile: "err.log",
		LogFormat:   log.Ldate | log.Lmicroseconds,
		LogOut:      os.Stderr,
	}
	loggersConfigs = make([]logConfig, 3)
	loggersConfigs = append(loggersConfigs, infoLogger, warningLogger, errorLogger)
	for _, loggerConfig := range loggersConfigs {
		switch loggerConfig.LogType {
		case "Info":
			{
				loggers.Info = generateLogger(loggerConfig)
			}
		case "Warning":
			{
				loggers.Warn = generateLogger(loggerConfig)
			}
		case "Error":
			{
				loggers.Err = generateLogger(loggerConfig)
			}
		}
	}
}

func FetchLogger() LogType {
	return loggers
}

func generateLogger(logConfig logConfig) *log.Logger {
	return log.New(logConfig.LogOut, ansi.Color(logConfig.LogPrefix, logConfig.LogColor), logConfig.LogFormat)
}
