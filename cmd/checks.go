package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

const (
	statusOK = iota
	statusWarning
	statusFailure
	statusUnknown
)

// DCOSChecker defines an interface for a generic DC/OS check.
// ID() returns a check unique ID and RunCheck(...) returns a combined stdout/stderr, exit code and error.
type DCOSChecker interface {
	ID() string
	Run(context.Context, *CLIConfigFlags) (string, int, error)
}

// RunCheck is a helper function to run the check and emit the result.
func RunCheck(ctx context.Context, check DCOSChecker) {
	output, retCode, err := check.Run(ctx, DCOSConfig)
	if err != nil {
		logrus.Fatalf("Error executing %s: %s", check.ID(), err)
	}

	if output != "" {
		fmt.Println(output)
	}

	os.Exit(retCode)
}

// NewComponentCheck returns an initialized instance of *ComponentCheck.
func NewComponentCheck(name string) DCOSChecker {
	return &ComponentCheck{
		Name: name,
	}
}

// NewExecutableCheck returns an intiialized instance of *ExecutableCheck
func NewExecutableCheck(name string, args []string) DCOSChecker {
	return &ExecutableCheck{
		Name: name,
		Args: args,
	}
}
