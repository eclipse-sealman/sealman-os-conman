package main

import (
	"log"

	"github.com/eclipse-sealman/sealman-os-conman/jsonsocket"
	"github.com/eclipse-sealman/sealman-os-conman/mgmtd"
	"github.com/eclipse-sealman/sealman-os-conman/wifi"
	"github.com/godbus/dbus/v5"
)

var manager *wifi.WiFiManager

func setConfig(r wifi.WiFiConfig) {
	if err := manager.SetConfig(&r); err != nil {
		panic(err)
	}
}

func changeState(r wifi.WiFiConfig) {
	if r.Enabled == nil {
		panic("is_enabled is required")
	}

	if err := manager.AccessPointChangeState(*r.Enabled); err != nil {
		panic(err)
	}
}

func getConfig() wifi.WiFiConfig {
	config, err := manager.GetConfig()
	if err != nil {
		panic(err)
	}

	return *config
}

func restart() {
	if err := manager.AccessPointRestart(); err != nil {
		panic(err)
	}
}

func main() {
	conn, err := dbus.SystemBus()
	if err != nil {
		log.Fatalf("failed to connect to system bus: %v", err)
	}
	defer conn.Close()

	manager = wifi.NewWiFiManager(conn)

	jsonsocket.Handle("change_state", changeState)
	jsonsocket.Handle("set_config", setConfig)
	jsonsocket.Handle("get_config", getConfig)
	jsonsocket.Handle("restart", restart)

	listener, err := mgmtd.CreateMgmtdUnixListener("/run/mgmtd/wifi_daemon")
	if err != nil {
		log.Fatalf("failed to create an mgmtd listener: %v", err)
	}

	if err := jsonsocket.ListenAndServe(listener); err != nil {
		log.Fatal(err)
	}
}
