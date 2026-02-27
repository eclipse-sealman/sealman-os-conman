package wifi

import (
	"errors"
	"fmt"

	"github.com/eclipse-sealman/sealman-os-conman/nm"
	"github.com/godbus/dbus/v5"
)

const (
	AccessPointID = "wifi1-ap"
	InterfaceName = "wifi1"
)

type WiFiManager struct {
	nm       *nm.NetworkManager
	settings *nm.Settings
	device   *nm.Device
}

func NewWiFiManager(conn *dbus.Conn) *WiFiManager {
	networkManager := nm.NewNetworkManager(conn)
	wifiDevice, err := networkManager.GetDeviceByIpIface(InterfaceName)
	if err != nil {
		panic(err)
	}

	return &WiFiManager{nm: networkManager, settings: nm.NewSettings(conn), device: wifiDevice}
}

func (m *WiFiManager) Activate(connection *nm.ConnectionProfile) (*nm.ActiveConnection, error) {
	return m.nm.ActivateConnectionOnDevice(connection, m.device)
}

func (m *WiFiManager) Deactivate() error {
	active, err := m.device.ActiveConnection()
	if err != nil {
		return err
	}

	if active == nil {
		return nil
	}

	id, err := active.Id()
	if err != nil {
		return err
	}

	if id != AccessPointID {
		return nil
	}

	return m.nm.DeactivateConnection(active)
}

func (m *WiFiManager) AccessPointChangeState(enabled bool) error {
	profile, err := m.AccessPointGetConnection()
	if err != nil {
		return err
	}

	if profile == nil && enabled {
		return errors.New("access point is not configured")
	} else if profile == nil {
		return nil
	}

	if enabled {
		err = profile.SetAutoconnect(true)
		if err != nil {
			return err
		}

		_, err := m.Activate(profile)
		if err != nil {
			return fmt.Errorf("activation failed: %w", err)
		}

	} else {
		err = profile.SetAutoconnect(false)
		if err != nil {
			return err
		}

		err = m.Deactivate()
		if err != nil {
			return fmt.Errorf("deactivation failed: %w", err)
		}
	}

	return nil
}

func (m *WiFiManager) AccessPointGetConnection() (*nm.ConnectionProfile, error) {
	profile, err := m.settings.FindConnectionById(AccessPointID)
	if err != nil {
		return nil, err
	}

	return profile, nil
}

func (m *WiFiManager) AddConnection(settings map[string]map[string]dbus.Variant) (*nm.ConnectionProfile, error) {
	return m.settings.AddConnection(settings)
}

func (m *WiFiManager) GetConfig() (*WiFiConfig, error) {
	activeConnection, err := m.device.ActiveConnection()
	if err != nil {
		return nil, err
	}

	enabled := false
	if activeConnection != nil {
		id, err := activeConnection.Id()
		if err != nil {
			return nil, err
		}
		if id == AccessPointID {
			enabled = true
		}
	}

	profile, err := m.AccessPointGetConnection()
	if err != nil {
		return nil, err
	}

	config := &WiFiConfig{Enabled: &enabled}
	if profile != nil {
		accessPointConfig, err := AcessPointGetConfig(profile)
		if err != nil {
			return nil, err
		}
		config.AP = accessPointConfig
	}

	return config, nil
}

func AcessPointGetConfig(c *nm.ConnectionProfile) (*AccessPointPConfig, error) {
	settings, err := c.GetSettings()
	if err != nil {
		return nil, err
	}

	ssid, hidden, channel, err := nm.ParseWirelessConfig(settings)
	if err != nil {
		return nil, err
	}

	auth, key, encryption, err := nm.ParseSecurityConfig(c, settings)
	if err != nil {
		return nil, err
	}

	ips, subnets, gateway, err := nm.ParseIPv4Config(settings)
	if err != nil {
		return nil, err
	}

	return &AccessPointPConfig{
		SSID:           ssid,
		Hidden:         hidden,
		Channel:        channel,
		Authentication: auth,
		Key:            key,
		Encryption:     encryption,
		IP:             ips,
		Subnet:         subnets,
		Gateway:        gateway,
	}, nil
}
