"""
Support for Hysen Heating Thermostat Controller.
Hysen HY03-1-Wifi device and derivative
"""

import asyncio
from functools import partial
import binascii
import socket
import logging
import voluptuous as vol
from homeassistant.helpers import config_validation as cv, entity_platform, service
from datetime import datetime

from homeassistant.components.climate import (
    PLATFORM_SCHEMA, 
    ClimateEntity
)

from homeassistant.components.climate.const import (
    DOMAIN,
    ATTR_HVAC_MODE,
    ATTR_MAX_TEMP,
    ATTR_MIN_TEMP,
    CURRENT_HVAC_HEAT,
    CURRENT_HVAC_IDLE,
    CURRENT_HVAC_OFF,
    HVAC_MODE_AUTO,
    HVAC_MODE_HEAT,
    HVAC_MODE_OFF,
    PRESET_NONE,
    SERVICE_SET_HVAC_MODE,
    SERVICE_SET_TEMPERATURE ,
    SUPPORT_PRESET_MODE,
    SUPPORT_TARGET_TEMPERATURE
)

from homeassistant.const import (
    ATTR_ENTITY_ID,
    ATTR_TEMPERATURE,
    CONF_HOST, 
    CONF_MAC, 
    CONF_NAME, 
    CONF_TIMEOUT,
    PRECISION_HALVES,
    SERVICE_TURN_OFF,
    SERVICE_TURN_ON,  
    STATE_ON, 
    STATE_OFF,
    STATE_LOCKED,
    STATE_UNLOCKED,
    STATE_OPEN,
    STATE_CLOSED,
    TEMP_CELSIUS, 
)

from hysen import (
    HysenHeatingDevice,
    HYSENHEAT_KEY_LOCK_OFF,
    HYSENHEAT_KEY_LOCK_ON,
    HYSENHEAT_POWER_OFF,
    HYSENHEAT_POWER_ON,
    HYSENHEAT_VALVE_OFF,
    HYSENHEAT_VALVE_ON,
    HYSENHEAT_MANUAL_IN_AUTO_OFF,
    HYSENHEAT_MANUAL_IN_AUTO_ON,
    HYSENHEAT_MODE_MANUAL,
    HYSENHEAT_MODE_AUTO,
    HYSENHEAT_SCHEDULE_12345_67,
    HYSENHEAT_SCHEDULE_123456_7,
    HYSENHEAT_SCHEDULE_1234567,
    HYSENHEAT_SENSOR_INTERNAL,
    HYSENHEAT_SENSOR_EXTERNAL,
    HYSENHEAT_SENSOR_INT_EXT,
    HYSENHEAT_HYSTERESIS_MIN,
    HYSENHEAT_HYSTERESIS_MAX,
    HYSENHEAT_CALIBRATION_MIN,
    HYSENHEAT_CALIBRATION_MAX,
    HYSENHEAT_FROST_PROTECTION_OFF,
    HYSENHEAT_FROST_PROTECTION_ON,
    HYSENHEAT_POWERON_OFF,
    HYSENHEAT_POWERON_ON,
    HYSENHEAT_MAX_TEMP,
    HYSENHEAT_MIN_TEMP,
    HYSENHEAT_WEEKDAY_MONDAY,
    HYSENHEAT_WEEKDAY_SUNDAY
)

_LOGGER = logging.getLogger(__name__)

DEFAULT_NAME = "Hysen Heating Thermostat"

PRESET_SCHEDULED = "Scheduled"
PRESET_MANUAL    = "Manual"
PRESET_TEMPORARY = "Temporary"

STATE_SENSOR_INTERNAL   = "internal"
STATE_SENSOR_EXTERNAL   = "external"
STATE_SENSOR_INT_EXT    = "int_ext"

STATE_SCHEDULE_12345_67 = "12345"
STATE_SCHEDULE_123456_7 = "123456"
STATE_SCHEDULE_1234567  = "1234567"

DEVICE_MIN_TEMP        = HYSENHEAT_MIN_TEMP
DEVICE_MAX_TEMP        = HYSENHEAT_MAX_TEMP
DEVICE_HYSTERESIS_MIN  = HYSENHEAT_HYSTERESIS_MIN
DEVICE_HYSTERESIS_MAX  = HYSENHEAT_HYSTERESIS_MAX
DEVICE_CALIBRATION_MIN = HYSENHEAT_CALIBRATION_MIN
DEVICE_CALIBRATION_MAX = HYSENHEAT_CALIBRATION_MAX
DEVICE_WEEKDAY_MONDAY  = HYSENHEAT_WEEKDAY_MONDAY
DEVICE_WEEKDAY_SUNDAY  = HYSENHEAT_WEEKDAY_SUNDAY

HYSEN_KEY_LOCK_TO_HASS = {
    HYSENHEAT_KEY_LOCK_OFF : STATE_UNLOCKED,
    HYSENHEAT_KEY_LOCK_ON  : STATE_LOCKED,
}

HASS_KEY_LOCK_TO_HYSEN = {
    STATE_UNLOCKED : HYSENHEAT_KEY_LOCK_OFF,
    STATE_LOCKED   : HYSENHEAT_KEY_LOCK_ON,
}

HYSEN_VALVE_STATE_TO_HASS = {
    HYSENHEAT_VALVE_ON  : STATE_OPEN,
    HYSENHEAT_VALVE_OFF : STATE_CLOSED,
}

HYSEN_POWER_STATE_TO_HASS = {
    HYSENHEAT_POWER_ON  : STATE_ON,
    HYSENHEAT_POWER_OFF : STATE_OFF,
}

HASS_POWER_STATE_TO_HYSEN = {
    STATE_ON  : HYSENHEAT_POWER_ON,
    STATE_OFF : HYSENHEAT_POWER_OFF,
}

HYSEN_SENSOR_TO_HASS = {
    HYSENHEAT_SENSOR_INTERNAL : STATE_SENSOR_INTERNAL,
    HYSENHEAT_SENSOR_EXTERNAL : STATE_SENSOR_EXTERNAL,
    HYSENHEAT_SENSOR_INT_EXT  : STATE_SENSOR_INT_EXT,
}

HASS_SENSOR_TO_HYSEN = {
    STATE_SENSOR_INTERNAL : HYSENHEAT_SENSOR_INTERNAL,
    STATE_SENSOR_EXTERNAL : HYSENHEAT_SENSOR_EXTERNAL,
    STATE_SENSOR_INT_EXT  : HYSENHEAT_SENSOR_INT_EXT,
}

HYSEN_FROST_PROTECTION_TO_HASS = {
    HYSENHEAT_FROST_PROTECTION_ON  : STATE_ON,
    HYSENHEAT_FROST_PROTECTION_OFF : STATE_OFF,
}

HASS_FROST_PROTECTION_TO_HYSEN = {
    STATE_ON  : HYSENHEAT_FROST_PROTECTION_ON,
    STATE_OFF : HYSENHEAT_FROST_PROTECTION_OFF,
}

HYSEN_POWERON_TO_HASS = {
    HYSENHEAT_POWERON_ON  : STATE_ON,
    HYSENHEAT_POWERON_OFF : STATE_OFF,
}

HASS_POWERON_TO_HYSEN = {
    STATE_ON  : HYSENHEAT_POWERON_ON,
    STATE_OFF : HYSENHEAT_POWERON_OFF,
}

HYSEN_SCHEDULE_TO_HASS = {
    HYSENHEAT_SCHEDULE_12345_67 : STATE_SCHEDULE_12345_67,
    HYSENHEAT_SCHEDULE_123456_7 : STATE_SCHEDULE_123456_7,
    HYSENHEAT_SCHEDULE_1234567  : STATE_SCHEDULE_1234567,
}

HASS_SCHEDULE_TO_HYSEN = {
    STATE_SCHEDULE_12345_67 : HYSENHEAT_SCHEDULE_12345_67,
    STATE_SCHEDULE_123456_7 : HYSENHEAT_SCHEDULE_123456_7,
    STATE_SCHEDULE_1234567  : HYSENHEAT_SCHEDULE_1234567,
}

HYSEN_MANUAL_IN_AUTO_TO_HASS = {
    HYSENHEAT_MANUAL_IN_AUTO_ON  : STATE_ON,
    HYSENHEAT_MANUAL_IN_AUTO_OFF : STATE_OFF,
}

HYSEN_MODE_TO_HASS = {
    HYSENHEAT_MODE_MANUAL : HVAC_MODE_HEAT,
    HYSENHEAT_MODE_AUTO   : HVAC_MODE_AUTO,
}

HASS_MODE_TO_HYSEN = {
    HVAC_MODE_HEAT : HYSENHEAT_MODE_MANUAL,
    HVAC_MODE_AUTO : HYSENHEAT_MODE_AUTO,
}

DATA_KEY = 'climate.hysen_heating'

ATTR_FWVERSION                = 'fwversion'
ATTR_KEY_LOCK                 = 'key_lock'
ATTR_POWER_STATE              = 'power_state'
ATTR_VALVE_STATE              = 'valve_state'
ATTR_MANUAL_IN_AUTO           = 'manual_in_auto'
ATTR_SENSOR                   = 'sensor'
ATTR_ROOM_TEMP                = 'room_temp'
ATTR_EXTERNAL_TEMP            = 'external_temp'
ATTR_EXTERNAL_MAX_TEMP        = 'external_max_temp'
ATTR_HYSTERESIS               = 'hysteresis'
ATTR_CALIBRATION              = 'calibration'
ATTR_FROST_PROTECTION         = 'frost_protection'
ATTR_POWERON                  = 'poweron'
ATTR_TIME_NOW                 = 'now'
ATTR_DEVICE_TIME              = 'time'
ATTR_DEVICE_WEEKDAY           = 'weekday'
ATTR_WEEKLY_SCHEDULE          = 'weekly_schedule'
ATTR_PERIOD1_TIME             = 'period1_time'
ATTR_PERIOD1_TEMP             = 'period1_temp'
ATTR_PERIOD2_TIME             = 'period2_time'
ATTR_PERIOD2_TEMP             = 'period2_temp'
ATTR_PERIOD3_TIME             = 'period3_time'
ATTR_PERIOD3_TEMP             = 'period3_temp'
ATTR_PERIOD4_TIME             = 'period4_time'
ATTR_PERIOD4_TEMP             = 'period4_temp'
ATTR_PERIOD5_TIME             = 'period5_time'
ATTR_PERIOD5_TEMP             = 'period5_temp'
ATTR_PERIOD6_TIME             = 'period6_time'
ATTR_PERIOD6_TEMP             = 'period6_temp'
ATTR_WE_PERIOD1_TIME          = 'we_period1_time'
ATTR_WE_PERIOD1_TEMP          = 'we_period1_temp'
ATTR_WE_PERIOD2_TIME          = 'we_period2_time'
ATTR_WE_PERIOD2_TEMP          = 'we_period2_temp'

SERVICE_SET_KEY_LOCK          = 'set_key_lock'
SERVICE_SET_SENSOR            = 'set_sensor'
SERVICE_SET_EXTERNAL_MAX_TEMP = 'set_external_max_temp'
SERVICE_SET_HYSTERESIS        = 'set_hysteresis'
SERVICE_SET_CALIBRATION       = 'set_calibration'
SERVICE_SET_MAX_TEMP          = 'set_max_temp'
SERVICE_SET_MIN_TEMP          = 'set_min_temp'
SERVICE_SET_FROST_PROTECTION  = 'set_frost_protection'
SERVICE_SET_POWERON           = 'set_poweron'
SERVICE_SET_TIME              = 'set_time'
SERVICE_SET_SCHEDULE          = 'set_schedule'

CONF_SYNC_CLOCK = 'sync_clock'
CONF_SYNC_HOUR  = 'sync_hour'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Optional(CONF_NAME, default = DEFAULT_NAME): cv.string,
        vol.Required(CONF_HOST): cv.string,
        vol.Required(CONF_MAC): cv.string,
        vol.Optional(CONF_TIMEOUT, default = 10): cv.positive_int, 
        vol.Optional(CONF_SYNC_CLOCK, default = False): cv.boolean,
        vol.Optional(CONF_SYNC_HOUR, default = 4): vol.All(vol.Coerce(int), vol.Clamp(min = 0, max = 23)),
    }
)

async def async_setup_platform(hass, config, async_add_entities, discovery_info = None):
    """Set up the Hysen heating thermostat platform."""
    if DATA_KEY not in hass.data:
        hass.data[DATA_KEY] = {}

    host = config.get(CONF_HOST)
    name = config.get(CONF_NAME)
    mac_addr = binascii.unhexlify(config.get(CONF_MAC).encode().replace(b':', b''))
    timeout = config.get(CONF_TIMEOUT)
    sync_clock = config.get(CONF_SYNC_CLOCK)
    sync_hour = config.get(CONF_SYNC_HOUR)
   
    hysen_device = HysenHeatingDevice((host, 80), mac_addr, timeout, sync_clock, sync_hour)
    
    device = HysenHeating(name, hysen_device, host)
    hass.data[DATA_KEY][host] = device

    async_add_entities([device], update_before_add = True)

    platform = entity_platform.current_platform.get()

    platform.async_register_entity_service(
        SERVICE_SET_KEY_LOCK,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Required(ATTR_KEY_LOCK): vol.In([STATE_UNLOCKED, STATE_LOCKED]),
        },
        HysenHeating.async_set_key_lock.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_SENSOR,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Required(ATTR_SENSOR): vol.In([STATE_SENSOR_INTERNAL, STATE_SENSOR_EXTERNAL, STATE_SENSOR_INT_EXT]),
        },
        HysenHeating.async_set_sensor.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_HVAC_MODE,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Required(ATTR_HVAC_MODE): vol.In([HVAC_MODE_OFF, HVAC_MODE_HEAT, HVAC_MODE_AUTO]),
        },
        HysenHeating.async_set_hvac_mode.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_TEMPERATURE,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Required(ATTR_TEMPERATURE): vol.All(
                vol.Coerce(int), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)
            ),
        },
        HysenHeating.async_set_temperature.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_TURN_ON,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
        },
        HysenHeating.async_turn_on.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_TURN_OFF,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
        },
        HysenHeating.async_turn_off.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_EXTERNAL_MAX_TEMP,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Required(ATTR_EXTERNAL_MAX_TEMP): vol.All(
                vol.Coerce(int), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)
            ),
        },
        HysenHeating.async_set_external_max_temp.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_HYSTERESIS,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Required(ATTR_HYSTERESIS): vol.All(
                vol.Coerce(int), vol.Clamp(min = DEVICE_HYSTERESIS_MIN, max = DEVICE_HYSTERESIS_MAX)
            ),
        },
        HysenHeating.async_set_hysteresis.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_CALIBRATION,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Required(ATTR_CALIBRATION): vol.All(
                vol.Coerce(float), vol.Clamp(min = DEVICE_CALIBRATION_MIN, max = DEVICE_CALIBRATION_MAX)
            ),      
        },
        HysenHeating.async_set_calibration.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_MAX_TEMP,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Required(ATTR_MAX_TEMP): vol.All(
                vol.Coerce(int), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)
            ),
        },
        HysenHeating.async_set_max_temp.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_MIN_TEMP,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Required(ATTR_MIN_TEMP): vol.All(
                vol.Coerce(int), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)
            ),
        },
        HysenHeating.async_set_min_temp.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_FROST_PROTECTION,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Required(ATTR_FROST_PROTECTION): vol.In([STATE_ON, STATE_OFF]),
        },
        HysenHeating.async_set_frost_protection.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_POWERON,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Required(ATTR_POWERON): vol.In([STATE_ON, STATE_OFF]),
        },
        HysenHeating.async_set_poweron.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_TIME,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Optional(ATTR_TIME_NOW): cv.boolean,
            vol.Optional(ATTR_DEVICE_TIME): cv.time,
            vol.Optional(ATTR_DEVICE_WEEKDAY): vol.All(
                vol.Coerce(int), vol.Clamp(min = DEVICE_WEEKDAY_MONDAY, max = DEVICE_WEEKDAY_SUNDAY)
            ),
         },
        HysenHeating.async_set_time.__name__,
    )

    platform.async_register_entity_service(
        SERVICE_SET_SCHEDULE,
        {
            vol.Required(ATTR_ENTITY_ID): cv.entity_ids,
            vol.Optional(ATTR_WEEKLY_SCHEDULE): vol.In([STATE_SCHEDULE_12345_67, STATE_SCHEDULE_123456_7, STATE_SCHEDULE_1234567]),
            vol.Optional(ATTR_PERIOD1_TIME): cv.time,
            vol.Optional(ATTR_PERIOD1_TEMP): vol.All(vol.Coerce(float), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)),
            vol.Optional(ATTR_PERIOD2_TIME): cv.time,
            vol.Optional(ATTR_PERIOD2_TEMP): vol.All(vol.Coerce(float), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)),
            vol.Optional(ATTR_PERIOD3_TIME): cv.time,
            vol.Optional(ATTR_PERIOD3_TEMP): vol.All(vol.Coerce(float), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)),
            vol.Optional(ATTR_PERIOD4_TIME): cv.time,
            vol.Optional(ATTR_PERIOD4_TEMP): vol.All(vol.Coerce(float), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)),
            vol.Optional(ATTR_PERIOD5_TIME): cv.time,
            vol.Optional(ATTR_PERIOD5_TEMP): vol.All(vol.Coerce(float), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)),
            vol.Optional(ATTR_PERIOD6_TIME): cv.time,
            vol.Optional(ATTR_PERIOD6_TEMP): vol.All(vol.Coerce(float), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)),
            vol.Optional(ATTR_WE_PERIOD1_TIME): cv.time,
            vol.Optional(ATTR_WE_PERIOD1_TEMP): vol.All(vol.Coerce(float), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)),
            vol.Optional(ATTR_WE_PERIOD2_TIME): cv.time,
            vol.Optional(ATTR_WE_PERIOD2_TEMP): vol.All(vol.Coerce(float), vol.Clamp(min = DEVICE_MIN_TEMP, max = DEVICE_MAX_TEMP)),
        },
        HysenHeating.async_set_schedule.__name__,
    )

class HysenHeating(ClimateEntity):
    """Representation of a Hysen Heating device."""

    def __init__(self, name, hysen_device, host):
        """Initialize the Hysen Heating device."""
        self._name = name
        self._hysen_device = hysen_device
        self._host = host

        self._available = False

    @property
    def unique_id(self):
        """Return a unique ID."""
        return self._unique_id
        
    @property
    def name(self):
        """Returns the name of the device."""
        return self._name

    @property
    def state(self):
        """Return current state."""
        return self.hvac_mode

    @property
    def precision(self):
        """Return the precision of the system."""
        return PRECISION_HALVES

    @property
    def temperature_unit(self):
        """Returns the unit of measurement which this thermostat uses."""
        return TEMP_CELSIUS

    @property
    def hvac_mode(self):
        """Return the current operation mode."""
        if self.is_on:
            return self._hvac_mode
        else:
            return HVAC_MODE_OFF

    @property
    def hvac_modes(self):
        """Returns the list of available operation modes."""
        if self.is_on:
            if self._manual_in_auto == STATE_ON:
                return [HVAC_MODE_OFF, HVAC_MODE_AUTO]
            else:
                return [HVAC_MODE_OFF, HVAC_MODE_HEAT, HVAC_MODE_AUTO]

        else:
            return [HVAC_MODE_OFF]

    @property
    def hvac_action(self):
        """Return the current running hvac operation."""
        if self.is_on:
            if self._valve_state == STATE_CLOSED:
                return CURRENT_HVAC_IDLE
            else:
                return CURRENT_HVAC_HEAT
        else:
            return CURRENT_HVAC_OFF

    @property
    def preset_mode(self):
        """Return the current preset mode, e.g., manual, scheduled, temporary."""
        if self.is_on:
            if self._manual_in_auto == STATE_ON:
                return PRESET_TEMPORARY
            if self._hvac_mode == HVAC_MODE_AUTO:
                return PRESET_SCHEDULED
            else:
                return PRESET_MANUAL
        else:
            return PRESET_NONE

    @property
    def preset_modes(self):
        """Return a list of available preset modes."""
        if self.is_on:
            if self._manual_in_auto == STATE_ON:
                return [PRESET_TEMPORARY]
            if self._hvac_mode == HVAC_MODE_AUTO:
                return [PRESET_SCHEDULED]
            else:
                return [PRESET_MANUAL]
        else:
            return [PRESET_NONE]

    @property
    def current_temperature(self):
        """Returns the sensor temperature."""
        if self._sensor == STATE_SENSOR_EXTERNAL:
            return self._external_temp
        else:
            return self._room_temp

    @property
    def target_temperature(self):
        """Returns the target temperature."""
        if self.is_on:
            return self._target_temp
        else:
            return None
   
    @property
    def target_temperature_step(self):
        """Returns the supported step of target temperature."""
        return PRECISION_HALVES

    @property
    def supported_features(self):
        """Returns the list of supported features."""
        return SUPPORT_PRESET_MODE | SUPPORT_TARGET_TEMPERATURE

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return self._available

    @property
    def min_temp(self):
        """Returns the minimum supported temperature."""
        return self._min_temp

    @property
    def max_temp(self):
        """Returns the maximum supported temperature."""
        return self._max_temp

    @property
    def device_state_attributes(self):
        """Return the specific state attributes of the device."""
        attrs = {}
        if self._available:
            attrs.update({
                ATTR_FWVERSION: self._fwversion,
                ATTR_HVAC_MODE: self._hvac_mode,
                ATTR_VALVE_STATE: self._valve_state,
                ATTR_KEY_LOCK: self._key_lock,
                ATTR_POWER_STATE: self._power_state,
                ATTR_MANUAL_IN_AUTO: self._manual_in_auto,
                ATTR_SENSOR: self._sensor,
                ATTR_ROOM_TEMP: self._room_temp,
                ATTR_EXTERNAL_TEMP: self._external_temp,
                ATTR_EXTERNAL_MAX_TEMP: self._external_max_temp,
                ATTR_HYSTERESIS: self._hysteresis,
                ATTR_CALIBRATION: self._calibration,
                ATTR_MAX_TEMP: self._max_temp,
                ATTR_MIN_TEMP: self._min_temp,
                ATTR_FROST_PROTECTION: self._frost_protection,
                ATTR_POWERON: self._poweron,
                ATTR_DEVICE_TIME: self._device_time,
                ATTR_DEVICE_WEEKDAY: self._device_weekday,
                ATTR_WEEKLY_SCHEDULE: self._schedule,
                ATTR_PERIOD1_TIME: self._period1_time,
                ATTR_PERIOD1_TEMP: self._period1_temp,
                ATTR_PERIOD2_TIME: self._period2_time,
                ATTR_PERIOD2_TEMP: self._period2_temp,
                ATTR_PERIOD3_TIME: self._period3_time,
                ATTR_PERIOD3_TEMP: self._period3_temp,
                ATTR_PERIOD4_TIME: self._period4_time,
                ATTR_PERIOD4_TEMP: self._period4_temp,
                ATTR_PERIOD5_TIME: self._period5_time,
                ATTR_PERIOD5_TEMP: self._period5_temp,
                ATTR_PERIOD6_TIME: self._period6_time,
                ATTR_PERIOD6_TEMP: self._period6_temp,
                ATTR_WE_PERIOD1_TIME: self._we_period1_time,
                ATTR_WE_PERIOD1_TEMP: self._we_period1_temp,
                ATTR_WE_PERIOD2_TIME: self._we_period2_time,
                ATTR_WE_PERIOD2_TEMP: self._we_period2_temp,
            })
        return attrs

    @property
    def is_on(self):
        """Return true if device is on."""
        return self._power_state == STATE_ON

    async def async_set_temperature(self, **kwargs):
        """Set new target temperature."""
        temp = float(kwargs.get(ATTR_TEMPERATURE))
        await self._async_try_command(
            "Error in set_temperature", 
            self._hysen_device.set_target_temp, 
            temp)

    async def async_set_external_max_temp(self, external_max_temp):
        """Set external limit temperature."""
        await self._async_try_command(
            "Error in async_set_external_max_temp", 
            self._hysen_device.set_external_max_temp, 
            external_max_temp)
        
    async def async_set_hvac_mode(self, hvac_mode):
        """Set hvac mode."""
        if hvac_mode not in [HVAC_MODE_OFF, HVAC_MODE_HEAT, HVAC_MODE_AUTO]:
            _LOGGER.error("[%s] Error in async_set_hvac_mode. Unknown hvac mode \'%s\'.", 
                self._host,
                hvac_mode)
            return
        if hvac_mode == HVAC_MODE_OFF:
            if self.is_on:
                await self.async_turn_off()
            else:
                await self.async_turn_on()
        else:
            await self._async_try_command(
                "Error in set_operation_mode", 
                self._hysen_device.set_operation_mode, 
                HASS_MODE_TO_HYSEN[hvac_mode])

    async def async_turn_on(self):
        """Turn device on."""
        await self._async_try_command(
            "Error in turn_on", 
            self._hysen_device.set_power, 
            HASS_POWER_STATE_TO_HYSEN[STATE_ON])

    async def async_turn_off(self):
        """Turn device off."""
        await self._async_try_command(
            "Error in turn_off", 
            self._hysen_device.set_power, 
            HASS_POWER_STATE_TO_HYSEN[STATE_OFF])

    async def async_set_key_lock(self, key_lock):
        """Set key lock Unlocked/Locked"""
        await self._async_try_command(
            "Error in set_key_lock", 
            self._hysen_device.set_key_lock, 
            HASS_KEY_LOCK_TO_HYSEN[key_lock])

    async def async_set_hysteresis(self, hysteresis):
        """Set hysteresis"""
        await self._async_try_command(
            "Error in set_hysteresis", 
            self._hysen_device.set_hysteresis, 
            hysteresis)

    async def async_set_calibration(self, calibration):
        """Set temperature calibration. 
           Range -5~+5 degree Celsius in 0.5 degree Celsius step."""
        await self._async_try_command(
            "Error in set_calibration", 
            self._hysen_device.set_calibration, 
            calibration)

    async def async_set_max_temp(self, max_temp):
        """Set temperature upper limit."""
        await self._async_try_command(
            "Error in set_max_temp", 
            self._hysen_device.set_max_temp, 
            max_temp)

    async def async_set_min_temp(self, min_temp):
        """Set temperature lower limit."""
        await self._async_try_command(
            "Error in set_min_temp", 
            self._hysen_device.set_min_temp, 
            min_temp)

    async def async_set_sensor(self, sensor):
        """Set sensor type"""
        await self._async_try_command(
            "Error in set_sensor", 
            self._hysen_device.set_sensor, 
            HASS_SENSOR_TO_HYSEN[sensor])

    async def async_set_frost_protection(self, frost_protection):
        """Set frost_protection 
           Off = No frost protection 
           On = Keeps the room temp between 5 to 7 degree when device is turned off."""
        await self._async_try_command(
            "Error in set_frost_protection", 
            self._hysen_device.set_frost_protection, 
            HASS_FROST_PROTECTION_TO_HYSEN[frost_protection])

    async def async_set_poweron(self, poweron):
        """Set poweron"""
        await self._async_try_command(
            "Error in set_poweron", 
            self._hysen_device.set_poweron, 
            HASS_POWERON_TO_HYSEN[poweron])

    async def async_set_time(self, now = None, time = None, weekday = None):
        """Set device time or to system time."""
        await self._async_try_command(
            "Error in set_time",
            self._hysen_device.set_time,
            datetime.now().hour if now else (None if time is None else time.hour),
            datetime.now().minute if now else (None if time is None else time.minute),
            datetime.now().second if now else (None if time is None else time.second),
            datetime.now().isoweekday() if now else weekday)

    async def async_set_schedule(
                                 self, 
                                 weekly_schedule = None,
                                 period1_time = None,
                                 period1_temp = None,
                                 period2_time = None,
                                 period2_temp = None,
                                 period3_time = None,
                                 period3_temp = None,
                                 period4_time = None,
                                 period4_temp = None,
                                 period5_time = None,
                                 period5_temp = None,
                                 period6_time = None,
                                 period6_temp = None,
                                 we_period1_time = None,
                                 we_period1_temp = None,
                                 we_period2_time = None,
                                 we_period2_temp = None
                                 ):
        """Set schedule ."""
        """Set weekly schedule mode 
           today = Daily schedule valid for today 
           12345 = Daily schedule valid from Monday to Friday
           123456 = Daily schedule valid from Monday to Saturday 
           1234567 = Daily schedule valid from Monday to Sunday
           Set daily schedule in 6 periods for working days and 2 periods for weekend"""
        if weekly_schedule is not None:
            await self._async_try_command(
                "Error in set_weekly_schedule", 
                self._hysen_device.set_weekly_schedule, 
                HASS_SCHEDULE_TO_HYSEN[weekly_schedule])
        """Set daily period 1."""
        await self._async_try_command(
            "Error in set_period1", 
            self._hysen_device.set_period1, 
            None if period1_time is None else period1_time.hour, 
            None if period1_time is None else period1_time.minute, 
            period1_temp)
        """Set daily period 2."""
        await self._async_try_command(
            "Error in set_period2", 
            self._hysen_device.set_period2, 
            None if period2_time is None else period2_time.hour, 
            None if period2_time is None else period2_time.minute, 
            period2_temp)
        """Set daily period 3."""
        await self._async_try_command(
            "Error in set_period3", 
            self._hysen_device.set_period3, 
            None if period3_time is None else period3_time.hour, 
            None if period3_time is None else period3_time.minute, 
            period3_temp)
        """Set daily period 4."""
        await self._async_try_command(
            "Error in set_period4", 
            self._hysen_device.set_period4, 
            None if period4_time is None else period4_time.hour, 
            None if period4_time is None else period4_time.minute, 
            period4_temp)
        """Set daily period 5."""
        await self._async_try_command(
            "Error in set_period5", 
            self._hysen_device.set_period5, 
            None if period5_time is None else period5_time.hour, 
            None if period5_time is None else period5_time.minute, 
            period5_temp)
        """Set daily period 6."""
        await self._async_try_command(
            "Error in set_period6", 
            self._hysen_device.set_period6, 
            None if period6_time is None else period6_time.hour, 
            None if period6_time is None else period6_time.minute, 
            period6_temp)
        """Set daily weekend period 1."""
        await self._async_try_command(
            "Error in set_we_period1", 
            self._hysen_device.set_we_period1, 
            None if we_period1_time is None else we_period1_time.hour, 
            None if we_period1_time is None else we_period1_time.minute, 
            we_period1_temp)
        """Set daily weekend period 2."""
        await self._async_try_command(
            "Error in set_we_period2", 
            self._hysen_device.set_we_period2, 
            None if we_period2_time is None else we_period2_time.hour, 
            None if we_period2_time is None else we_period2_time.minute, 
            we_period2_temp)

    async def _async_try_command(self, mask_error, func, *args, **kwargs):
        """Calls a device command and handle error messages."""
        self._available = True
        try:
            await self.hass.async_add_executor_job(partial(func, *args, **kwargs))
        except Exception as exc:
            _LOGGER.error("[%s] %s %s: %s", self._host, self._name, mask_error, exc)
            self._available = False

    async def async_update(self):
        """Get the latest state from the device."""
        await self._async_try_command(
            "Error in get_device_status",
            self._hysen_device.get_device_status)
        self._unique_id = self._hysen_device.unique_id
        self._fwversion = self._hysen_device.fwversion
        self._key_lock = str(HYSEN_KEY_LOCK_TO_HASS[self._hysen_device.key_lock])
        self._manual_in_auto = str(HYSEN_MANUAL_IN_AUTO_TO_HASS[self._hysen_device.manual_in_auto])
        self._valve_state = str(HYSEN_VALVE_STATE_TO_HASS[self._hysen_device.valve_state])
        self._power_state = str(HYSEN_POWER_STATE_TO_HASS[self._hysen_device.power_state])
        self._room_temp = float(self._hysen_device.room_temp)
        self._target_temp = float(self._hysen_device.target_temp)
        if self._hysen_device.operation_mode > 1:
            _LOGGER.error("[%s] hvac mode \'%s\'.", 
                    self._host,
                    self._hysen_device.operation_mode)
        self._hvac_mode = str(HYSEN_MODE_TO_HASS[self._hysen_device.operation_mode])
        self._schedule = str(HYSEN_SCHEDULE_TO_HASS[self._hysen_device.schedule])
        self._sensor = str(HYSEN_SENSOR_TO_HASS[self._hysen_device.sensor])
        self._external_max_temp = float(self._hysen_device.external_max_temp)
        self._hysteresis = int(self._hysen_device.hysteresis)
        self._max_temp = int(self._hysen_device.max_temp)
        self._min_temp = int(self._hysen_device.min_temp)
        self._calibration = float(self._hysen_device.calibration)
        self._frost_protection = str(HYSEN_FROST_PROTECTION_TO_HASS[self._hysen_device.frost_protection])
        self._poweron = str(HYSEN_POWERON_TO_HASS[self._hysen_device.poweron])
        self._unknown1 = self._hysen_device.unknown1
        self._external_temp = float(self._hysen_device.external_temp)
        self._device_time = str(self._hysen_device.clock_hour).zfill(2) + ":" + str(self._hysen_device.clock_minute).zfill(2) + ":" + str(self._hysen_device.clock_second).zfill(2)
        self._device_weekday = int(self._hysen_device.clock_weekday)
        self._period1_time = str(self._hysen_device.period1_hour).zfill(2) + ":" + str(self._hysen_device.period1_min).zfill(2)
        self._period2_time = str(self._hysen_device.period2_hour).zfill(2) + ":" + str(self._hysen_device.period2_min).zfill(2)
        self._period3_time = str(self._hysen_device.period3_hour).zfill(2) + ":" + str(self._hysen_device.period3_min).zfill(2)
        self._period4_time = str(self._hysen_device.period4_hour).zfill(2) + ":" + str(self._hysen_device.period4_min).zfill(2)
        self._period5_time = str(self._hysen_device.period5_hour).zfill(2) + ":" + str(self._hysen_device.period5_min).zfill(2)
        self._period6_time = str(self._hysen_device.period6_hour).zfill(2) + ":" + str(self._hysen_device.period6_min).zfill(2)
        self._we_period1_time = str(self._hysen_device.we_period1_hour).zfill(2) + ":" + str(self._hysen_device.we_period1_min).zfill(2)
        self._we_period2_time = str(self._hysen_device.we_period2_hour).zfill(2) + ":" + str(self._hysen_device.we_period2_min).zfill(2)
        self._period1_temp = float(self._hysen_device.period1_temp)
        self._period2_temp = float(self._hysen_device.period2_temp)
        self._period3_temp = float(self._hysen_device.period3_temp)
        self._period4_temp = float(self._hysen_device.period4_temp)
        self._period5_temp = float(self._hysen_device.period5_temp)
        self._period6_temp = float(self._hysen_device.period6_temp)
        self._we_period1_temp = float(self._hysen_device.we_period1_temp)
        self._we_period2_temp = float(self._hysen_device.we_period2_temp)
        self._unknown2 = self._hysen_device.unknown2
        self._unknown3 = self._hysen_device.unknown3
     