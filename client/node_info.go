package client

import (
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/dcos/dcos-go/dcos"
	"github.com/dcos/dcos-go/dcos/nodeutil"
)

// override the defaultStateURL to use https scheme
var defaultStateURL = url.URL{
	Scheme: "https",
	Host:   net.JoinHostPort(dcos.DNSRecordLeader, strconv.Itoa(dcos.PortMesosMaster)),
	Path:   "/state",
}

// NewNodeInfo returns a new NodeInfo implementation.
func NewNodeInfo(client *http.Client, role, detectIP string, forceTLS bool) (nodeutil.NodeInfo, error) {
	var options []nodeutil.Option
	if forceTLS {
		options = append(options, nodeutil.OptionMesosStateURL(defaultStateURL.String()))
	}

	if detectIP != "" {
		options = append(options, nodeutil.OptionDetectIP(detectIP))
	}

	return nodeutil.NewNodeInfo(client, role, options...)
}
