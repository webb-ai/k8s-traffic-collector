package replay

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
)

var errNoDefaultRoute = errors.New("no default route found")
var zeroRouteBytes = []byte("00000000")
var procNetRoutePath = "/proc/net/route"

var defaultLinuxInterface = "eth0"
var defaultWindowsInterface = "Ethernet 2"
var defaultDarwinInterface = "en0"

const maxProcNetRouteRead = 1000

type DefaultRouteDetails struct {
	// InterfaceName is the interface name. It must always be populated.
	// It's like "eth0" (Linux), "Ethernet 2" (Windows), "en0" (macOS).
	InterfaceName string

	// InterfaceDesc is populated on Windows at least. It's a
	// longer description, like "Red Hat VirtIO Ethernet Adapter".
	InterfaceDesc string

	// InterfaceIndex is like net.Interface.Index.
	// Zero means not populated.
	InterfaceIndex int
}

func DefaultRouteInterface(fallback string) string {
	dr, err := DefaultRoute()
	if err != nil {
		if fallback != "" {
			return fallback
		}

		switch runtime.GOOS {
		case "linux":
			return defaultLinuxInterface
		case "windows":
			return defaultWindowsInterface
		case "darwin":
			return defaultDarwinInterface
		default:
			return defaultLinuxInterface
		}
	}
	return dr.InterfaceName
}

func DefaultRoute() (DefaultRouteDetails, error) {
	return defaultRoute()
}

func defaultRoute() (d DefaultRouteDetails, err error) {
	v, err := defaultRouteInterfaceProcNet()
	if err == nil {
		d.InterfaceName = v
		return d, nil
	}

	return defaultRouteFromNetlink()
}

// returns string interface name and an error.
// io.EOF: full route table processed, no default route found.
// other io error: something went wrong reading the route file.
func defaultRouteInterfaceProcNet() (string, error) {
	rc, err := defaultRouteInterfaceProcNetInternal(128)
	if rc == "" && (errors.Is(err, io.EOF) || err == nil) {
		// https://github.com/google/gvisor/issues/5732
		// On a regular Linux kernel you can read the first 128 bytes of /proc/net/route,
		// then come back later to read the next 128 bytes and so on.
		//
		// In Google Cloud Run, where /proc/net/route comes from gVisor, you have to
		// read it all at once. If you read only the first few bytes then the second
		// read returns 0 bytes no matter how much originally appeared to be in the file.
		//
		// At the time of this writing (Mar 2021) Google Cloud Run has eth0 and eth1
		// with a 384 byte /proc/net/route. We allocate a large buffer to ensure we'll
		// read it all in one call.
		return defaultRouteInterfaceProcNetInternal(4096)
	}
	return rc, err
}

func defaultRouteFromNetlink() (d DefaultRouteDetails, err error) {
	c, err := rtnetlink.Dial(&netlink.Config{Strict: true})
	if err != nil {
		return d, fmt.Errorf("defaultRouteFromNetlink: Dial: %w", err)
	}
	defer c.Close()
	rms, err := c.Route.List()
	if err != nil {
		return d, fmt.Errorf("defaultRouteFromNetlink: List: %w", err)
	}
	for _, rm := range rms {
		if rm.Attributes.Gateway == nil {
			// A default route has a gateway. If it doesn't, skip it.
			continue
		}
		if rm.Attributes.Dst != nil {
			continue
		}
		idx := int(rm.Attributes.OutIface)
		if idx == 0 {
			continue
		}
		if iface, err := net.InterfaceByIndex(idx); err == nil {
			d.InterfaceName = iface.Name
			d.InterfaceIndex = idx
			return d, nil
		}
	}
	return d, errNoDefaultRoute
}

func defaultRouteInterfaceProcNetInternal(bufsize int) (string, error) {
	f, err := os.Open(procNetRoutePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, bufsize)
	lineNum := 0
	for {
		lineNum++
		line, err := br.ReadSlice('\n')
		if err == io.EOF || lineNum > maxProcNetRouteRead {
			return "", errNoDefaultRoute
		}
		if err != nil {
			return "", err
		}
		if !bytes.Contains(line, zeroRouteBytes) {
			continue
		}
		fields := strings.Fields(string(line))
		ifc := fields[0]
		ip := fields[1]
		netmask := fields[7]

		if strings.HasPrefix(ifc, "tailscale") ||
			strings.HasPrefix(ifc, "wg") {
			continue
		}
		if ip == "00000000" && netmask == "00000000" {
			// default route
			return ifc, nil // interface name
		}
	}
}
