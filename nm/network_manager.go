package nm

import (
	"fmt"

	"github.com/godbus/dbus/v5"
)

const (
	NMService = "org.freedesktop.NetworkManager"
	NMPath    = "/org/freedesktop/NetworkManager"
)

// https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html
type NetworkManager struct {
	conn *dbus.Conn
	obj  dbus.BusObject
}

func NewNetworkManager(conn *dbus.Conn) *NetworkManager {
	return &NetworkManager{conn: conn, obj: conn.Object(NMService, NMPath)}
}

func (n *NetworkManager) ActivateConnection(
	connection *ConnectionProfile,
	device *Device,
	specificObject dbus.ObjectPath,
) (*ActiveConnection, error) {
	if connection == nil {
		return nil, fmt.Errorf("connection must not be nil")
	}

	if device == nil {
		return nil, fmt.Errorf("device must not be nil")
	}

	var activePath dbus.ObjectPath
	call := n.obj.Call(NMService+".ActivateConnection", 0, connection.obj.Path(), device.obj.Path(), specificObject)
	if call.Err != nil {
		return nil, fmt.Errorf("ActivateConnection failed: %w", call.Err)
	}

	if err := call.Store(&activePath); err != nil {
		return nil, fmt.Errorf("failed to extract active connection path: %w", err)
	}

	return NewActiveConnection(n.conn, activePath), nil
}

func (n *NetworkManager) DeactivateConnection(active *ActiveConnection) error {
	if active == nil {
		return nil
	}

	call := n.obj.Call(NMService+".DeactivateConnection", 0, active.obj.Path())
	if call.Err != nil {
		return fmt.Errorf("DeactivateConnection failed: %w", call.Err)
	}

	return nil
}

func (n *NetworkManager) ActivateConnectionOnDevice(connection *ConnectionProfile, device *Device) (*ActiveConnection, error) {
	return n.ActivateConnection(connection, device, dbus.ObjectPath("/"))
}

func (n *NetworkManager) GetDeviceByIpIface(iface string) (*Device, error) {
	if iface == "" {
		return nil, fmt.Errorf("iface must not be empty")
	}

	var path dbus.ObjectPath

	call := n.obj.Call(NMService+".GetDeviceByIpIface", 0, iface)
	if call.Err != nil {
		return nil, fmt.Errorf("GetDeviceByIpIface failed: %w", call.Err)
	}

	if err := call.Store(&path); err != nil {
		return nil, fmt.Errorf("failed to extract device path: %w", err)
	}

	if path == "" || path == "/" {
		return nil, fmt.Errorf("no device found for iface %q", iface)
	}

	return NewDevice(n.conn, path), nil
}
