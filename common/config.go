package common

import (
	"net"
	"net/http"

	"github.com/dcos/dcos-checks/client"
	"github.com/pkg/errors"
)

var (
	// DCOSConfig is a global variable contains CLI options.
	DCOSConfig = new(CLIConfigFlags)
)

// CLIConfigFlags consolidates CLI cobra flags
type CLIConfigFlags struct {
	// CACert is a path to DC/OS CA authority file.
	CACert string

	// Verbose enabled debugging output with logrus.Debug(...)
	Verbose bool

	// ForceTLS forces to use HTTPS over HTTP schema.
	ForceTLS bool

	// IAMConfig is a path to identity and access managment config.
	IAMConfig string

	// Role defines DC/OS node's role. Valid roles are: master, agent, agent_public
	// defined in "github.com/dcos/dcos-go/dcos" package.
	Role string

	// DetectIP is a path to detect_ip script. Usually must be /opt/mesosphere/bin/detect_ip
	DetectIP string

	// NodeIPStr describes an IP address. This option will override the output of DetectIP.
	NodeIPStr string
}

// IP returns a valid IP address. If NodeIPStr is set, it will be used. Otherwise DetectIP will be executed
// and output will be returned.
func (cli *CLIConfigFlags) IP(c *http.Client) (net.IP, error) {
	if cli.NodeIPStr != "" {
		ip := net.ParseIP(cli.NodeIPStr)
		if ip == nil {
			return nil, errors.Errorf("invalid IP address %s", cli.NodeIPStr)
		}
		return ip, nil
	}

	// NodeIPStr is empty at this point. Now execute a command DetectIP variable.
	nodeInfo, err := client.NewNodeInfo(c, cli.Role, cli.DetectIP, cli.ForceTLS)
	if err != nil {
		return nil, err
	}

	return nodeInfo.DetectIP()
}
