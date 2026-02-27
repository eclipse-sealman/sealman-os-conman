package nm

import (
	"fmt"

	"github.com/godbus/dbus/v5"
)

// exists only to simplify testing
type propertyGetter interface {
	GetProperty(p string) (dbus.Variant, error)
}

func castVariant[T any](v dbus.Variant, name string) (T, error) {
	var zero T

	val, ok := v.Value().(T)
	if !ok {
		return zero, fmt.Errorf(
			"%s has unexpected type %T, expected %T",
			name,
			v.Value(),
			zero,
		)
	}

	return val, nil
}

func getVariantValue[T any](m map[string]dbus.Variant, key string) (T, error) {
	var zero T

	v, ok := m[key]
	if !ok {
		return zero, fmt.Errorf("%s not found", key)
	}

	return castVariant[T](v, key)
}

func getPropertyValue[T any](obj propertyGetter, prop string) (T, error) {
	var zero T

	v, err := obj.GetProperty(prop)
	if err != nil {
		return zero, err
	}

	return castVariant[T](v, prop)
}

func getSection(settings map[string]map[string]dbus.Variant, section string) (map[string]dbus.Variant, error) {
	sec, ok := settings[section]
	if !ok {
		return nil, fmt.Errorf("%s section not found", section)
	}

	return sec, nil
}
