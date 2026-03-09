package nm

import (
	"fmt"
	"slices"

	"github.com/godbus/dbus/v5"
)

const settingsConnectionInterface = "org.freedesktop.NetworkManager.Settings.Connection"

// https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Settings.Connection.html
type ConnectionProfile struct {
	conn *dbus.Conn
	obj  dbus.BusObject
}

func NewConnectionProfile(conn *dbus.Conn, path dbus.ObjectPath) *ConnectionProfile {
	return &ConnectionProfile{conn: conn, obj: conn.Object(NMService, path)}
}

func (c *ConnectionProfile) GetSettings() (map[string]map[string]dbus.Variant, error) {
	var out map[string]map[string]dbus.Variant

	call := c.obj.Call(settingsConnectionInterface+".GetSettings", 0)
	if call.Err != nil {
		return nil, fmt.Errorf("GetSettings failed: %w", call.Err)
	}

	if err := call.Store(&out); err != nil {
		return nil, fmt.Errorf("failed to extract settings: %w", err)
	}

	return out, nil
}

func (c *ConnectionProfile) Update(settings map[string]map[string]dbus.Variant) error {
	if err := c.obj.Call(settingsConnectionInterface+".Update", 0, settings).Err; err != nil {
		return fmt.Errorf("Update failed: %w", err)
	}
	return nil
}

func (c *ConnectionProfile) Delete() error {
	if err := c.obj.Call(settingsConnectionInterface+".Delete", 0).Err; err != nil {
		return fmt.Errorf("Delete failed: %w", err)
	}
	return nil
}

func (c *ConnectionProfile) Id() (string, error) {
	settings, err := c.GetSettings()
	if err != nil {
		return "", err
	}

	sec, err := getSection(settings, "connection")
	if err != nil {
		return "", err
	}

	return getVariantValue[string](sec, "id")
}

func (c *ConnectionProfile) GetSecrets(setting string) (map[string]map[string]dbus.Variant, error) {
	var out map[string]map[string]dbus.Variant

	call := c.obj.Call(settingsConnectionInterface+".GetSecrets", 0, setting)
	if call.Err != nil {
		return nil, fmt.Errorf("GetSecrets failed: %w", call.Err)
	}

	if err := call.Store(&out); err != nil {
		return nil, fmt.Errorf("failed to extract secrets: %w", err)
	}

	return out, nil
}

func (c *ConnectionProfile) GetPSK() (string, error) {
	secrets, err := c.GetSecrets("802-11-wireless-security")
	if err != nil {
		return "", err
	}

	sec, err := getSection(secrets, "802-11-wireless-security")
	if err != nil {
		return "", err
	}

	psk, err := getVariantValue[string](sec, "psk")
	if err != nil {
		return "", err
	}

	return psk, nil
}

func ParseIPv4Config(settings map[string]map[string]dbus.Variant) ([]string, []int, string, error) {
	ipv4, err := getSection(settings, "ipv4")
	if err != nil {
		return nil, nil, "", nil
	}

	method, err := getVariantValue[string](ipv4, "method")
	if err != nil || method != "manual" {
		return nil, nil, "", nil
	}

	var ips []string
	var subnets []int

	addrData, err := getVariantValue[[]map[string]dbus.Variant](ipv4, "address-data")
	if err == nil {
		for i, entry := range addrData {
			ip, err := getVariantValue[string](entry, "address")
			if err != nil {
				return nil, nil, "", fmt.Errorf("address-data[%d]: %w", i, err)
			}

			prefix, err := getVariantValue[uint32](entry, "prefix")
			if err != nil {
				return nil, nil, "", fmt.Errorf("address-data[%d]: %w", i, err)
			}

			ips = append(ips, ip)
			subnets = append(subnets, int(prefix))
		}
	}

	gateway, _ := getVariantValue[string](ipv4, "gateway")

	return ips, subnets, gateway, nil
}

func ParseSecurityConfig(c *ConnectionProfile, settings map[string]map[string]dbus.Variant) (string, string, []string, error) {
	sec, err := getSection(settings, "802-11-wireless-security")
	if err != nil {
		return "", "", nil, nil
	}

	var auth string
	if km, err := getVariantValue[string](sec, "key-mgmt"); err == nil {
		proto, _ := getVariantValue[[]string](sec, "proto")
		pmf, _ := getVariantValue[int32](sec, "pmf")

		switch km {
		case "wpa-psk":
			if slices.Compare(proto, []string{"rsn"}) == 0 {
				if pmf == 2 {
					auth = "wpa2-wpa3"
				} else {
					auth = "wpa2-psk"
				}
			} else {
				auth = "wpa-psk"
			}

		case "sae":
			auth = "wpa3-sae"
		}
	}

	key, _ := c.GetPSK()

	encryption, _ := getVariantValue[[]string](sec, "pairwise")

	return auth, key, encryption, nil
}

func ParseWirelessConfig(settings map[string]map[string]dbus.Variant) (string, bool, int, error) {
	wireless, err := getSection(settings, "802-11-wireless")
	if err != nil {
		return "", false, 0, err
	}

	ssidBytes, _ := getVariantValue[[]byte](wireless, "ssid")
	ssid := string(ssidBytes)

	hidden, _ := getVariantValue[bool](wireless, "hidden")
	channelU32, _ := getVariantValue[uint32](wireless, "channel")
	channel := int(channelU32)

	return ssid, hidden, channel, nil
}

func (c *ConnectionProfile) SetAutoconnect(enabled bool) error {
	settings, err := c.GetSettings()
	if err != nil {
		return err
	}

	connSection, err := getSection(settings, "connection")
	if err != nil {
		return err
	}

	connSection["autoconnect"] = dbus.MakeVariant(enabled)

	// settings may contain deprecated values in wrong format that cause update to fail
	sanitizeIPSettings(settings)

	return c.Update(settings)
}

func sanitizeIPSettings(settings map[string]map[string]dbus.Variant) {
	deprecatedKeys := []string{"addresses", "routes"}

	for _, sectionName := range []string{"ipv4", "ipv6"} {
		if section, ok := settings[sectionName]; ok {
			for _, key := range deprecatedKeys {
				delete(section, key)
			}
		}
	}
}
