package wifi

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/godbus/dbus/v5"
)

type WiFiConfig struct {
	Enabled *bool  `json:"is_enabled"`
	Mode    string `json:"mode"` // client | ap

	AP *AccessPointConfig `json:"ap,omitempty"` // this section is optional
}

type AccessPointConfig struct {
	SSID           string   `json:"ssid"`
	Hidden         bool     `json:"hidden"`
	Authentication string   `json:"authentication"`
	Key            string   `json:"key"`
	Channel        int      `json:"channel"`
	IP             []string `json:"ip"`
	Subnet         []int    `json:"subnet"`
	Gateway        string   `json:"gateway"`
	Encryption     []string `json:"encryption"`
}

func (cfg *AccessPointConfig) Validate() error {
	if len(cfg.IP) == 0 {
		return fmt.Errorf("at least one IPv4 address must be provided")
	}

	if len(cfg.IP) != len(cfg.Subnet) {
		return fmt.Errorf(
			"ip and subnet length mismatch: got %d IPs and %d subnets",
			len(cfg.IP),
			len(cfg.Subnet),
		)
	}

	for i := range cfg.IP {
		ip, err := netip.ParseAddr(cfg.IP[i])
		if err != nil || !ip.Is4() {
			return fmt.Errorf("invalid IPv4 address: %s", cfg.IP[i])
		}

		prefix := cfg.Subnet[i]
		if prefix < 0 || prefix > 32 {
			return fmt.Errorf("invalid subnet prefix: %d", prefix)
		}
	}

	if cfg.Gateway != "" {
		gateway, err := netip.ParseAddr(cfg.Gateway)
		if err != nil || !gateway.Is4() {
			return fmt.Errorf("invalid IPv4 gateway: %s", cfg.Gateway)
		}
	}

	// TODO
	// we support only channels 1-11 for now
	// if cfg.Channel <= 0 || cfg.Channel > 165 {
	// 	return fmt.Errorf("invalid wifi channel: %d", cfg.Channel)
	// }

	if cfg.Channel <= 0 || cfg.Channel > 11 {
		return fmt.Errorf("invalid wifi channel: %d, choose a value in range 1-11", cfg.Channel)
	}

	validEncryption := []string{"ccmp", "tkip"}
	if len(cfg.Encryption) > 2 {
		return fmt.Errorf("invalid encryption length: %v, use at most two values: %v", cfg.Encryption, validEncryption)
	}

	for _, encryption := range cfg.Encryption {
		if !slices.Contains(validEncryption, encryption) {
			return fmt.Errorf("invalid encryption: %q, choose from %v", encryption, validEncryption)
		}
	}

	return nil
}

func (cfg *AccessPointConfig) BuildSettings() (map[string]map[string]dbus.Variant, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	band := "bg"
	if cfg.Channel >= 36 {
		band = "a"
	}

	addressData := make([]map[string]dbus.Variant, 0, len(cfg.IP))
	for i := range cfg.IP {
		addressData = append(addressData, map[string]dbus.Variant{
			"address": dbus.MakeVariant(cfg.IP[i]),
			"prefix":  dbus.MakeVariant(uint32(cfg.Subnet[i])),
		})
	}

	settings := map[string]map[string]dbus.Variant{
		"connection": {
			"id":             dbus.MakeVariant(AccessPointID),
			"type":           dbus.MakeVariant("802-11-wireless"),
			"interface-name": dbus.MakeVariant(InterfaceName),
		},
		"802-11-wireless": {
			"ssid":    dbus.MakeVariant([]byte(cfg.SSID)),
			"mode":    dbus.MakeVariant("ap"),
			"hidden":  dbus.MakeVariant(cfg.Hidden),
			"band":    dbus.MakeVariant(band),
			"channel": dbus.MakeVariant(uint32(cfg.Channel)),
		},
		"ipv4": {
			"method":       dbus.MakeVariant("manual"),
			"address-data": dbus.MakeVariant(addressData),
		},
		"ipv6": {
			"method": dbus.MakeVariant("ignore"),
		},
	}

	if cfg.Gateway != "" {
		settings["ipv4"]["gateway"] = dbus.MakeVariant(cfg.Gateway)
	}

	if cfg.Authentication != "" {
		var keyMgmt string
		var proto []string
		var pmf int

		switch cfg.Authentication {
		case "wpa-psk":
			keyMgmt = "wpa-psk"
			proto = []string{"wpa"}

		case "wpa2-psk":
			keyMgmt = "wpa-psk"
			proto = []string{"rsn"}

		case "wpa2-wpa3":
			keyMgmt = "wpa-psk"
			proto = []string{"rsn"}
			pmf = 2

		case "wpa3-sae":
			keyMgmt = "sae"
			proto = []string{"rsn"}
			pmf = 3

		default:
			return nil, fmt.Errorf("invalid authentication: %s", cfg.Authentication)
		}

		security := map[string]dbus.Variant{
			"key-mgmt": dbus.MakeVariant(keyMgmt),
			"proto":    dbus.MakeVariant(proto),
			"pmf":      dbus.MakeVariant(pmf),
		}

		if cfg.Key != "" {
			security["psk"] = dbus.MakeVariant(cfg.Key)
		}

		if len(cfg.Encryption) > 0 {
			security["pairwise"] = dbus.MakeVariant(cfg.Encryption)
			security["group"] = dbus.MakeVariant(cfg.Encryption)
		}

		settings["802-11-wireless-security"] = security
	}

	return settings, nil
}
