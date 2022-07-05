package common

import (
	"fmt"
	"io"
	"log"

	"github.com/meshplus/crypto"
)

//SuperLogger super logger
type SuperLogger interface {
	SetEnableCaller(enable bool)
	crypto.Logger
}

type logger struct {
	log   *log.Logger
	level int
}

func (l *logger) SetEnableCaller(enable bool) {
	if enable {
		l.log.SetFlags(log.LstdFlags | log.Lshortfile)
		return
	}
	l.log.SetFlags(log.LstdFlags)
}

func (l *logger) Debug(v ...interface{}) {
	if l.level > crypto.DEBUG {
		return
	}
	_ = l.log.Output(2, "[DEBU] "+fmt.Sprint(v...))
}
func (l *logger) Debugf(format string, v ...interface{}) {
	if l.level > crypto.DEBUG {
		return
	}
	_ = l.log.Output(2, "[DEBU] "+fmt.Sprintf(format, v...))
}
func (l *logger) Info(v ...interface{}) {
	if l.level > crypto.Info {
		return
	}
	_ = l.log.Output(2, "[INFO] "+fmt.Sprint(v...))
}
func (l *logger) Infof(format string, v ...interface{}) {
	if l.level > crypto.Info {
		return
	}
	_ = l.log.Output(2, "[INFO] "+fmt.Sprintf(format, v...))
}
func (l *logger) Notice(v ...interface{}) {
	if l.level > crypto.Notice {
		return
	}
	_ = l.log.Output(2, "[NOTI] "+fmt.Sprint(v...))
}
func (l *logger) Noticef(format string, v ...interface{}) {
	if l.level > crypto.Notice {
		return
	}
	_ = l.log.Output(2, "[NOTI] "+fmt.Sprintf(format, v...))
}
func (l *logger) Warning(v ...interface{}) {
	if l.level > crypto.Warning {
		return
	}
	_ = l.log.Output(2, "[WARN] "+fmt.Sprint(v...))
}
func (l *logger) Warningf(format string, v ...interface{}) {
	if l.level > crypto.Warning {
		return
	}
	_ = l.log.Output(2, "[WARN] "+fmt.Sprintf(format, v...))
}
func (l *logger) Error(v ...interface{}) {
	if l.level > crypto.Error {
		return
	}
	_ = l.log.Output(2, "[ERRO] "+fmt.Sprint(v...))
}
func (l *logger) Errorf(format string, v ...interface{}) {
	if l.level > crypto.Error {
		return
	}
	_ = l.log.Output(2, "[ERRO] "+fmt.Sprintf(format, v...))
}
func (l *logger) Critical(v ...interface{}) {
	_ = l.log.Output(2, "[CRIT] "+fmt.Sprint(v...))
}
func (l *logger) Criticalf(format string, v ...interface{}) {
	_ = l.log.Output(2, "[CRIT] "+fmt.Sprintf(format, v...))
}

//GetBasicLogger get basic Logger
func GetBasicLogger(writer io.Writer) crypto.Logger {
	return GetBasicLoggerWithLevel(writer, crypto.DEBUG)
}

//GetBasicLoggerWithLevel get basic Logger
func GetBasicLoggerWithLevel(writer io.Writer, level int) crypto.Logger {
	return &logger{
		log:   log.New(writer, "", log.LstdFlags|log.Lshortfile),
		level: level,
	}
}
