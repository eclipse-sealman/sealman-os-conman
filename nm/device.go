package nm

import (
	"github.com/godbus/dbus/v5"
)

const deviceInterface = "org.freedesktop.NetworkManager.Device"

// https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Device.html
type Device struct {
	conn *dbus.Conn
	obj  dbus.BusObject
}

func NewDevice(conn *dbus.Conn, path dbus.ObjectPath) *Device {
	return &Device{conn: conn, obj: conn.Object(NMService, path)}
}

func (d *Device) ActiveConnection() (*ActiveConnection, error) {
	path, err := getPropertyValue[dbus.ObjectPath](d.obj, deviceInterface+".ActiveConnection")
	if err != nil {
		return nil, err
	}

	if path == "/" {
		return nil, nil
	}

	return NewActiveConnection(d.conn, path), nil
}
