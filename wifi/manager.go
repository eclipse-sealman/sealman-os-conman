package wifi

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/eclipse-sealman/sealman-os-conman/nm"
	"github.com/godbus/dbus/v5"
)

const (
	AccessPointID    = "wifi1-ap"
	InterfaceName    = "wifi1"
	RegdomConfigPath = "/etc/eg/regdom.conf"
	RegdomGlobal     = "00"
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

func (m *WiFiManager) activate(connection *nm.ConnectionProfile) (*nm.ActiveConnection, error) {
	if err := connection.SetAutoconnect(true); err != nil {
		return nil, err
	}

	return m.nm.ActivateConnectionOnDevice(connection, m.device)
}

func (m *WiFiManager) deactivate(connection *nm.ConnectionProfile, connectionId string) error {
	if err := connection.SetAutoconnect(false); err != nil {
		return err
	}

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

	if id != connectionId {
		return nil
	}

	return m.nm.DeactivateConnection(active)
}

func (m *WiFiManager) AccessPointChangeState(enabled bool) error {
	if enabled {
		if err := m.AccessPointActivate(); err != nil {
			return fmt.Errorf("activation failed: %w", err)
		}

	} else {
		if err := m.AccessPointDeactivate(); err != nil {
			return fmt.Errorf("deactivation failed: %w", err)
		}
	}

	return nil
}

func (m *WiFiManager) AccessPointIsEnabled() (bool, error) {
	active, err := m.device.ActiveConnection()
	if err != nil {
		return false, err
	}

	if active == nil {
		return false, nil
	}

	id, err := active.Id()
	if err != nil {
		return false, err
	}

	return id == AccessPointID, nil
}

func (m *WiFiManager) AccessPointActivate() error {
	profile, err := m.AccessPointGetConnection()
	if err != nil {
		return err
	}

	if profile == nil {
		return errors.New("access point is not configured")
	}

	regdom, err := GetRegdom()
	if err != nil {
		return fmt.Errorf("failed to read regdom from %s", RegdomConfigPath)
	}

	if regdom == RegdomGlobal {
		return errors.New("failed to activate access point in global regdom")
	}

	_, err = m.activate(profile)
	return err
}

func (m *WiFiManager) AccessPointDeactivate() error {
	profile, err := m.AccessPointGetConnection()
	if err != nil {
		return err
	}

	if profile == nil {
		return nil
	}

	return m.deactivate(profile, AccessPointID)
}

func (m *WiFiManager) AccessPointRestart() error {
	enabled, err := m.AccessPointIsEnabled()
	if err != nil {
		return err
	}

	if !enabled {
		return nil
	}

	if err := m.AccessPointDeactivate(); err != nil {
		return err
	}

	return m.AccessPointActivate()
}

func (m *WiFiManager) AccessPointGetConnection() (*nm.ConnectionProfile, error) {
	profile, err := m.settings.FindConnectionById(AccessPointID)
	if err != nil {
		return nil, err
	}

	return profile, nil
}

func (m *WiFiManager) addConnection(settings map[string]map[string]dbus.Variant) (*nm.ConnectionProfile, error) {
	return m.settings.AddConnection(settings)
}

func (m *WiFiManager) SetConfig(config *WiFiConfig) error {
	profile, err := m.AccessPointGetConnection()
	if err != nil {
		return err
	}

	if config.AP != nil {
		desired, err := config.AP.BuildSettings()
		if err != nil {
			return err
		}

		if profile == nil {
			profile, err = m.addConnection(desired)
			if err != nil {
				return fmt.Errorf("failed to create connection: %w", err)
			}
		} else {
			if err := profile.Update(desired); err != nil {
				return fmt.Errorf("failed to update connection settings: %w", err)
			}
		}
	}

	if config.Enabled != nil {
		enabled := *config.Enabled
		if err = m.AccessPointChangeState(enabled); err != nil {
			return err
		}

		if !enabled && config.AP == nil && profile != nil {
			profile.Delete()
		}

	} else {
		if err := m.AccessPointRestart(); err != nil {
			panic(err)
		}
	}

	return nil
}

func (m *WiFiManager) GetConfig() (*WiFiConfig, error) {
	enabled, err := m.AccessPointIsEnabled()
	if err != nil {
		return nil, err
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

func AcessPointGetConfig(c *nm.ConnectionProfile) (*AccessPointConfig, error) {
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

	return &AccessPointConfig{
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

func GetRegdom() (string, error) {
	content, err := os.ReadFile(RegdomConfigPath)
	if err != nil {
		return "", err
	}
	regdom := strings.TrimSpace(string(content))
	return regdom, nil
}
