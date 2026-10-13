package securelog

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"regexp"
)

// Redact provider credentials and owned physical keys at the I/O logger boundary.
// Correlation prefixes stay outside the message and retain native diagnostics.
var urls = regexp.MustCompile(`https?://[^\s]+`)

type logger struct {
	logging.Logger
	values []string
}

func New(base logging.Logger, values ...string) logging.Logger {
	return &logger{Logger: base, values: values}
}
func (l *logger) message(format string, values ...any) string {
	message := fmt.Sprintf(format, values...)
	for _, value := range l.values {
		if value != "" {
			message = strings.ReplaceAll(message, value, "<redacted>")
			message = strings.ReplaceAll(message, url.PathEscape(value), "<redacted>")
			message = strings.ReplaceAll(message, url.QueryEscape(value), "<redacted>")
		}
	}
	return urls.ReplaceAllStringFunc(message, func(value string) string {
		parsed, err := url.Parse(value)
		if err != nil {
			return "<redacted-url>"
		}
		parsed.RawQuery = ""
		parsed.Fragment = ""
		parsed.User = nil
		return parsed.String()
	})
}
func (l *logger) Panic(f string, v ...any)   { l.Logger.Panic("%s", l.message(f, v...)) }
func (l *logger) Error(f string, v ...any)   { l.Logger.Error("%s", l.message(f, v...)) }
func (l *logger) Warning(f string, v ...any) { l.Logger.Warning("%s", l.message(f, v...)) }
func (l *logger) Info(f string, v ...any)    { l.Logger.Info("%s", l.message(f, v...)) }
func (l *logger) Debug(f string, v ...any)   { l.Logger.Debug("%s", l.message(f, v...)) }
func (l *logger) CopyWithPrefix(prefix string) logging.Logger {
	return New(l.Logger.CopyWithPrefix(prefix), l.values...)
}
