"""
Support for Hysen Thermostat Controller for floor heating.
Hysen HY03-1-Wifi device and derivative
http://www.xmhysen.com/products_detail/productId=197.html
"""

import asyncio
from functools import partial
import binascii
import socket
import logging

import voluptuous as vol

from homeassistant.components.climate import (
    ClimateDevice, 
    PLATFORM_SCHEMA
)

from homeassistant.components.climate.const import (
    DOMAIN,
    SUPPORT_TARGET_TEMPERATURE, 
    SUPPORT_OPERATION_MODE, 
    SUPPORT_ON_OFF,
    STATE_MANUAL, 
    STATE_AUTO
)

from homeassistant.const import (
    CONF_NAME, 
    CONF_HOST, 
    CONF_MAC, 
    CONF_TIMEOUT,
    TEMP_CELSIUS, 
    STATE_ON, 
    STATE_OFF,
    STATE_LOCKED,
    STATE_UNLOCKED,
    STATE_IDLE,
    STATE_OPEN,
    STATE_CLOSED,
    ATTR_TEMPERATURE,
    PRECISION_WHOLE,
    PRECISION_HALVES, 
    ATTR_ENTITY_ID
)
import homeassistant.helpers.config_validation as cv
import homeassistant.util.dt as dt_util

from .hysenheating_device import (
    HysenHeatingDevice,
    HYSEN_HEAT_REMOTE_LOCK_OFF,
    HYSEN_HEAT_REMOTE_LOCK_ON,
    HYSEN_HEAT_POWER_OFF,
    HYSEN_HEAT_POWER_ON,
    HYSEN_HEAT_VALVE_OFF,
    HYSEN_HEAT_VALVE_ON,
    HYSEN_HEAT_MANUAL_OVER_AUTO_OFF,
    HYSEN_HEAT_MANUAL_OVER_AUTO_ON,
    HYSEN_HEAT_MODE_MANUAL,
    HYSEN_HEAT_MODE_AUTO,
    HYSEN_HEAT_SCHEDULE_12345_67,
    HYSEN_HEAT_SCHEDULE_123456_7,
    HYSEN_HEAT_SCHEDULE_1234567,
    HYSEN_HEAT_SENSOR_INTERNAL,
    HYSEN_HEAT_SENSOR_EXTERNAL,
    HYSEN_HEAT_SENSOR_INT_EXT,
    HYSEN_HEAT_HYSTERESIS_MIN,
    HYSEN_HEAT_HYSTERESIS_MAX,
    HYSEN_HEAT_CALIBRATION_MIN,
    HYSEN_HEAT_CALIBRATION_MAX,
    HYSEN_HEAT_FROST_PROTECTION_OFF,
    HYSEN_HEAT_FROST_PROTECTION_ON,
    HYSEN_HEAT_POWERON_OFF,
    HYSEN_HEAT_POWERON_ON,
    HYSEN_HEAT_MAX_TEMP,
    HYSEN_HEAT_MIN_TEMP
)

_LOGGER = logging.getLogger(__name__)

SUPPORT_FLAGS = (SUPPORT_OPERATION_MODE | 
                 SUPPORT_ON_OFF | 
                 SUPPORT_TARGET_TEMPERATURE
)

STATE_SCHEDULE_12345_67 = "12345,67"
STATE_SCHEDULE_123456_7 = "12345,6"
STATE_SCHEDULE_1234567  = "1234567"

STATE_SENSOR_INTERNAL   = "internal"
STATE_SENSOR_EXTERNAL   = "external"
STATE_SENSOR_INT_EXT    = "int_ext"

#STATE_IDLE              = "off"

KEY_LOCK_MODES = [
    STATE_UNLOCKED, 
    STATE_LOCKED 
]

SCHEDULE_MODES = [
    STATE_SCHEDULE_12345_67, 
    STATE_SCHEDULE_123456_7, 
    STATE_SCHEDULE_1234567 
]

OPERATION_MODES = [
    STATE_MANUAL, 
    STATE_AUTO,
    STATE_IDLE
]

HYSEN_KEY_LOCK_TO_HASS = {
    HYSEN_HEAT_REMOTE_LOCK_OFF : STATE_UNLOCKED,
    HYSEN_HEAT_REMOTE_LOCK_ON  : STATE_LOCKED,
}

HASS_KEY_LOCK_TO_HYSEN = {
    STATE_UNLOCKED : HYSEN_HEAT_REMOTE_LOCK_OFF,
    STATE_LOCKED   : HYSEN_HEAT_REMOTE_LOCK_ON,
}

HYSEN_POWERON_TO_HASS = {
    HYSEN_HEAT_POWERON_ON  : STATE_ON,
    HYSEN_HEAT_POWERON_OFF : STATE_OFF,
}

HYSEN_MANUAL_OVER_AUTO_TO_HASS = {
    HYSEN_HEAT_MANUAL_OVER_AUTO_ON  : STATE_ON,
    HYSEN_HEAT_MANUAL_OVER_AUTO_OFF : STATE_OFF,
}

HASS_MANUAL_OVER_AUTO_TO_HYSEN = {
    True  : HYSEN_HEAT_MANUAL_OVER_AUTO_ON,
    False : HYSEN_HEAT_MANUAL_OVER_AUTO_OFF,
}

HYSEN_VALVE_STATE_TO_HASS = {
    HYSEN_HEAT_VALVE_ON  : STATE_OPEN,
    HYSEN_HEAT_VALVE_OFF : STATE_CLOSED,
}

HYSEN_POWER_STATE_TO_HASS = {
    HYSEN_HEAT_POWER_ON  : STATE_ON,
    HYSEN_HEAT_POWER_OFF : STATE_OFF,
}

HASS_POWER_STATE_TO_HYSEN = {
    True  : HYSEN_HEAT_POWER_ON,
    False : HYSEN_HEAT_POWER_OFF,
}

HYSEN_SENSOR_TO_HASS = {
    HYSEN_HEAT_SENSOR_INTERNAL : STATE_SENSOR_INTERNAL,
    HYSEN_HEAT_SENSOR_EXTERNAL : STATE_SENSOR_EXTERNAL,
    HYSEN_HEAT_SENSOR_INT_EXT  : STATE_SENSOR_INT_EXT,
}

HASS_SENSOR_TO_HYSEN = {
    STATE_SENSOR_INTERNAL : HYSEN_HEAT_SENSOR_INTERNAL,
    STATE_SENSOR_EXTERNAL : HYSEN_HEAT_SENSOR_EXTERNAL,
    STATE_SENSOR_INT_EXT  : HYSEN_HEAT_SENSOR_INT_EXT,
}

HYSEN_FROST_PROTECTION_TO_HASS = {
    HYSEN_HEAT_FROST_PROTECTION_ON  : STATE_ON,
    HYSEN_HEAT_FROST_PROTECTION_OFF : STATE_OFF,
}

HASS_FROST_PROTECTION_TO_HYSEN = {
    True  : HYSEN_HEAT_FROST_PROTECTION_ON,
    False : HYSEN_HEAT_FROST_PROTECTION_OFF,
}

HYSEN_POWERON_TO_HASS = {
    HYSEN_HEAT_POWERON_ON  : STATE_ON,
    HYSEN_HEAT_POWERON_OFF : STATE_OFF,
}

HASS_POWERON_TO_HYSEN = {
    True  : HYSEN_HEAT_POWERON_ON,
    False : HYSEN_HEAT_POWERON_OFF,
}

HYSEN_SCHEDULE_TO_HASS = {
    HYSEN_HEAT_SCHEDULE_12345_67 : STATE_SCHEDULE_12345_67,
    HYSEN_HEAT_SCHEDULE_123456_7 : STATE_SCHEDULE_123456_7,
    HYSEN_HEAT_SCHEDULE_1234567  : STATE_SCHEDULE_1234567,
}

HASS_SCHEDULE_TO_HYSEN = {
    STATE_SCHEDULE_12345_67 : HYSEN_HEAT_SCHEDULE_12345_67,
    STATE_SCHEDULE_123456_7 : HYSEN_HEAT_SCHEDULE_123456_7,
    STATE_SCHEDULE_1234567  : HYSEN_HEAT_SCHEDULE_1234567,
}

HYSEN_MODE_TO_HASS = {
    HYSEN_HEAT_MODE_MANUAL : STATE_MANUAL,
    HYSEN_HEAT_MODE_AUTO   : STATE_AUTO,
}

HASS_MODE_TO_HYSEN = {
    STATE_MANUAL : HYSEN_HEAT_MODE_MANUAL,
    STATE_AUTO   : HYSEN_HEAT_MODE_AUTO,
}

HYSEN_HEATING   = 0x4EAD
DEFAULT_NAME    = 'Hysen Heating Thermostat'
DEFAULT_TIMEOUT = 10

DATA_KEY = 'climate.hysen_heating'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_NAME, default = DEFAULT_NAME): cv.string,
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_MAC): cv.string,
    vol.Optional(CONF_TIMEOUT, default = DEFAULT_TIMEOUT): cv.positive_int, 
})

ATTR_KEY_LOCK             = 'key_lock'
ATTR_VALVE_STATE          = 'valve_state'
ATTR_POWER_STATE          = 'power_state'
ATTR_MANUAL_OVER_AUTO     = 'manual_over_auto'
                                       
ATTR_SENSOR               = 'sensor'
ATTR_ROOM_TEMP            = 'room_temp'
ATTR_EXTERNAL_TEMP        = 'external_temp'
ATTR_EXTERNAL_TARGET_TEMP = 'external_limit_temp'
ATTR_HYSTERESIS           = 'hysteresis'
ATTR_CALIBRATION          = 'calibration'
ATTR_HEATING_MAX_TEMP     = 'max_temp'
ATTR_HEATING_MIN_TEMP     = 'min_temp'
ATTR_FROST_PROTECTION     = 'frost_protection'
ATTR_POWERON              = 'poweron'
ATTR_CLOCK_HOUR           = 'clock_hour'
ATTR_CLOCK_MIN            = 'clock_min'
ATTR_CLOCK_SEC            = 'clock_sec'
ATTR_CLOCK_WEEKDAY        = 'clock_weekday'
ATTR_SCHEDULE             = 'schedule'
ATTR_PERIOD_HOUR          = 'hour'
ATTR_PERIOD_MIN           = 'min'
ATTR_PERIOD_TEMP          = 'temp'
ATTR_PERIOD1_HOUR         = 'period1_hour'
ATTR_PERIOD1_MIN          = 'period1_min'
ATTR_PERIOD1_TEMP         = 'period1_temp'
ATTR_PERIOD2_HOUR         = 'period2_hour'
ATTR_PERIOD2_MIN          = 'period2_min'
ATTR_PERIOD2_TEMP         = 'period2_temp'
ATTR_PERIOD3_HOUR         = 'period3_hour'
ATTR_PERIOD3_MIN          = 'period3_min'
ATTR_PERIOD3_TEMP         = 'period3_temp'
ATTR_PERIOD4_HOUR         = 'period4_hour'
ATTR_PERIOD4_MIN          = 'period4_min'
ATTR_PERIOD4_TEMP         = 'period4_temp'
ATTR_PERIOD5_HOUR         = 'period5_hour'
ATTR_PERIOD5_MIN          = 'period5_min'
ATTR_PERIOD5_TEMP         = 'period5_temp'
ATTR_PERIOD6_HOUR         = 'period6_hour'
ATTR_PERIOD6_MIN          = 'period6_min'
ATTR_PERIOD6_TEMP         = 'period6_temp'
ATTR_WE_PERIOD1_HOUR      = 'we_period1_hour'
ATTR_WE_PERIOD1_MIN       = 'we_period1_min'
ATTR_WE_PERIOD1_TEMP      = 'we_period1_temp'
ATTR_WE_PERIOD6_HOUR      = 'we_period6_hour'
ATTR_WE_PERIOD6_MIN       = 'we_period6_min'
ATTR_WE_PERIOD6_TEMP      = 'we_period6_temp'

SERVICE_SET_KEY_LOCK         = 'hysenheat_set_key_lock'
SERVICE_SET_SENSOR           = 'hysenheat_set_sensor'
SERVICE_SET_HYSTERESIS       = 'hysenheat_set_hysteresis'
SERVICE_SET_CALIBRATION      = 'hysenheat_set_calibration'
SERVICE_SET_HEATING_MAX_TEMP = 'hysenheat_set_max_temp'
SERVICE_SET_HEATING_MIN_TEMP = 'hysenheat_set_min_temp'
SERVICE_SET_FROST_PROTECTION = 'hysenheat_set_frost_protection'
SERVICE_SET_POWERON          = 'hysenheat_set_poweron'
SERVICE_SET_TIME_NOW         = 'hysenheat_set_time_now'
SERVICE_SET_SCHEDULE         = 'hysenheat_set_schedule'
SERVICE_SET_PERIOD1          = 'hysenheat_set_period1'
SERVICE_SET_PERIOD2          = 'hysenheat_set_period2'
SERVICE_SET_PERIOD3          = 'hysenheat_set_period3'
SERVICE_SET_PERIOD4          = 'hysenheat_set_period4'
SERVICE_SET_PERIOD5          = 'hysenheat_set_period5'
SERVICE_SET_PERIOD6          = 'hysenheat_set_period6'
SERVICE_SET_WE_PERIOD1       = 'hysenheat_set_we_period1'
SERVICE_SET_WE_PERIOD6       = 'hysenheat_set_we_period6'

CLIMATE_SERVICE_SCHEMA = vol.Schema({
    vol.Optional(ATTR_ENTITY_ID): cv.entity_ids,
})

SERVICE_SCHEMA_KEY_LOCK = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Required(ATTR_KEY_LOCK): cv.string,
})

SERVICE_SCHEMA_SENSOR = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Required(ATTR_SENSOR): cv.string,
})

SERVICE_SCHEMA_HYSTERESIS = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Required(ATTR_HYSTERESIS): vol.Coerce(float),
})

SERVICE_SCHEMA_CALIBRATION = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Required(ATTR_CALIBRATION): vol.Coerce(float), 
})

SERVICE_SCHEMA_HEATING_MAX_TEMP = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Required(ATTR_HEATING_MAX_TEMP): vol.Coerce(int),
})

SERVICE_SCHEMA_HEATING_MIN_TEMP = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Required(ATTR_HEATING_MIN_TEMP): vol.Coerce(int),
})

SERVICE_SCHEMA_FROST_PROTECTION = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Required(ATTR_FROST_PROTECTION): vol.Boolean(),
})

SERVICE_SCHEMA_POWERON = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Required(ATTR_POWERON): vol.Boolean(),
})

SERVICE_SCHEMA_TIME_NOW = CLIMATE_SERVICE_SCHEMA

SERVICE_SCHEMA_SCHEDULE = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Required(ATTR_SCHEDULE): cv.string,
})

SERVICE_SCHEMA_PERIOD1 = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Optional(ATTR_PERIOD_HOUR): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_MIN): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_TEMP): vol.Coerce(float),
})

SERVICE_SCHEMA_PERIOD2 = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Optional(ATTR_PERIOD_HOUR): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_MIN): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_TEMP): vol.Coerce(float),
})

SERVICE_SCHEMA_PERIOD3 = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Optional(ATTR_PERIOD_HOUR): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_MIN): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_TEMP): vol.Coerce(float),
})

SERVICE_SCHEMA_PERIOD4 = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Optional(ATTR_PERIOD_HOUR): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_MIN): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_TEMP): vol.Coerce(float),
})

SERVICE_SCHEMA_PERIOD5 = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Optional(ATTR_PERIOD_HOUR): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_MIN): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_TEMP): vol.Coerce(float),
})

SERVICE_SCHEMA_PERIOD6 = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Optional(ATTR_PERIOD_HOUR): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_MIN): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_TEMP): vol.Coerce(float),
})

SERVICE_SCHEMA_WE_PERIOD1 = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Optional(ATTR_PERIOD_HOUR): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_MIN): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_TEMP): vol.Coerce(float),
})

SERVICE_SCHEMA_WE_PERIOD6 = CLIMATE_SERVICE_SCHEMA.extend({
    vol.Optional(ATTR_PERIOD_HOUR): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_MIN): vol.Coerce(int),
    vol.Optional(ATTR_PERIOD_TEMP): vol.Coerce(float),
})

SERVICE_TO_METHOD = {
    SERVICE_SET_KEY_LOCK: {
        'method': 'async_set_key_lock', 
        'schema': SERVICE_SCHEMA_KEY_LOCK
    },
    SERVICE_SET_SENSOR: {
        'method': 'async_set_sensor', 
        'schema': SERVICE_SCHEMA_SENSOR
    },
    SERVICE_SET_HYSTERESIS: {
        'method': 'async_set_hysteresis', 
        'schema': SERVICE_SCHEMA_HYSTERESIS
    },
    SERVICE_SET_CALIBRATION: {
        'method': 'async_set_calibration', 
        'schema': SERVICE_SCHEMA_CALIBRATION
    },
    SERVICE_SET_HEATING_MAX_TEMP: {
        'method': 'async_set_heating_max_temp', 
        'schema': SERVICE_SCHEMA_HEATING_MAX_TEMP
    },
    SERVICE_SET_HEATING_MIN_TEMP: {
        'method': 'async_set_heating_min_temp', 
        'schema': SERVICE_SCHEMA_HEATING_MIN_TEMP
    },
    SERVICE_SET_FROST_PROTECTION: {
        'method': 'async_set_frost_protection', 
        'schema': SERVICE_SCHEMA_FROST_PROTECTION
    },
    SERVICE_SET_POWERON: {
        'method': 'async_set_poweron', 
        'schema': SERVICE_SCHEMA_POWERON
    },
    SERVICE_SET_TIME_NOW: {
        'method': 'async_set_time_now', 
        'schema': SERVICE_SCHEMA_TIME_NOW
    },
    SERVICE_SET_SCHEDULE: {
        'method': 'async_set_schedule', 
        'schema': SERVICE_SCHEMA_SCHEDULE
    },
    SERVICE_SET_PERIOD1: {
        'method': 'async_set_period1', 
        'schema': SERVICE_SCHEMA_PERIOD1
    },
    SERVICE_SET_PERIOD2: {
        'method': 'async_set_period2', 
        'schema': SERVICE_SCHEMA_PERIOD2
    },
    SERVICE_SET_PERIOD3: {
        'method': 'async_set_period3', 
        'schema': SERVICE_SCHEMA_PERIOD3
    },
    SERVICE_SET_PERIOD4: {
        'method': 'async_set_period4', 
        'schema': SERVICE_SCHEMA_PERIOD4
    },
    SERVICE_SET_PERIOD5: {
        'method': 'async_set_period5', 
        'schema': SERVICE_SCHEMA_PERIOD5
    },
    SERVICE_SET_PERIOD6: {
        'method': 'async_set_period6', 
        'schema': SERVICE_SCHEMA_PERIOD6
    },
    SERVICE_SET_WE_PERIOD1: {
        'method': 'async_set_we_period1', 
        'schema': SERVICE_SCHEMA_WE_PERIOD1
    },
    SERVICE_SET_WE_PERIOD6: {
        'method': 'async_set_we_period6', 
        'schema': SERVICE_SCHEMA_WE_PERIOD6
    },
}

async def async_setup_platform(hass, config, async_add_entities, discovery_info = None):
    """Set up the Hysen heating thermostat platform."""
    if DATA_KEY not in hass.data:
        hass.data[DATA_KEY] = {}

    host = config.get(CONF_HOST)
    name = config.get(CONF_NAME)
    mac_addr = binascii.unhexlify(config.get(CONF_MAC).encode().replace(b':', b''))
    timeout = config.get(CONF_TIMEOUT)
    
    hysen_device = HysenHeatingDevice((host, 80), mac_addr, HYSEN_HEATING, timeout)
    
    device = HysenHeating(name, hysen_device, host)
    hass.data[DATA_KEY][host] = device

    async_add_entities([device], update_before_add = True)

    async def async_service_handler(service):
        """Map services to methods on target thermostat."""
        method = SERVICE_TO_METHOD.get(service.service)
        params = {key: value for key, value in service.data.items()
                  if key != ATTR_ENTITY_ID}
        entity_ids = service.data.get(ATTR_ENTITY_ID)
        if entity_ids:
            target_heatings = [dev for dev in hass.data[DATA_KEY].values()
                                  if dev.entity_id in entity_ids]
        else:
            target_heatings = hass.data[DATA_KEY].values()
 
        update_tasks = []
        for heating in target_heatings:
            await getattr(heating, method['method'])(**params)

        for heating in target_heatings:
            update_tasks.append(heating.async_update_ha_state(True))

        if update_tasks:
            await asyncio.wait(update_tasks, loop = hass.loop)

    for heating_service in SERVICE_TO_METHOD:
        schema = SERVICE_TO_METHOD[heating_service].get('schema', CLIMATE_SERVICE_SCHEMA)
        hass.services.async_register(
            DOMAIN, 
            heating_service, 
            async_service_handler, 
            schema = schema)

class HysenHeating(ClimateDevice):
    """Representation of a Hysen Heating device."""

    def __init__(self, name, hysen_device, host):
        """Initialize the Hysen Heating device."""
        self._name = name
        self._host = host
        self._hysen_device = hysen_device

        self._device_available = False
        self._device_authenticated = False

    @property
    def should_poll(self):
        """Return the polling state."""
        return True

    @property
    def name(self):
        """Returns the name of the device."""
        return self._name

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return self._device_available

    @property
    def state(self):
        """Return current state."""
        return HYSEN_POWER_STATE_TO_HASS[self._hysen_device.power_state]

    @property
    def precision(self):
        """Return the precision of the system."""
        return PRECISION_HALVES

    @property
    def device_state_attributes(self):
        """Return the specific state attributes of the device."""
        attr = {}
        if self._device_available:
            attr.update({
                ATTR_VALVE_STATE: str(HYSEN_VALVE_STATE_TO_HASS[self._hysen_device.valve_state]),
                ATTR_KEY_LOCK: str(HYSEN_KEY_LOCK_TO_HASS[self._hysen_device.remote_lock]),
                ATTR_POWER_STATE: str(HYSEN_POWER_STATE_TO_HASS[self._hysen_device.power_state]),
                ATTR_MANUAL_OVER_AUTO: str(HYSEN_MANUAL_OVER_AUTO_TO_HASS[self._hysen_device.manual_over_auto]),
                ATTR_SENSOR: str(HYSEN_SENSOR_TO_HASS[self._hysen_device.sensor]),
                ATTR_ROOM_TEMP: float(self._hysen_device.room_temp),
                ATTR_EXTERNAL_TEMP: float(self._hysen_device.external_temp),
                ATTR_EXTERNAL_TARGET_TEMP: float(self._hysen_device.external_limit_temp),
                ATTR_HYSTERESIS: int(self._hysen_device.hysteresis),
                ATTR_CALIBRATION: float(self._hysen_device.calibration),
                ATTR_HEATING_MAX_TEMP: int(self._hysen_device.max_temp),
                ATTR_HEATING_MIN_TEMP: int(self._hysen_device.min_temp),
                ATTR_FROST_PROTECTION: str(HYSEN_FROST_PROTECTION_TO_HASS[self._hysen_device.frost_protection]),
                ATTR_POWERON: str(HYSEN_POWERON_TO_HASS[self._hysen_device.poweron]),
                ATTR_CLOCK_HOUR: int(self._hysen_device.clock_hour),
                ATTR_CLOCK_MIN: int(self._hysen_device.clock_min),
                ATTR_CLOCK_SEC: int(self._hysen_device.clock_sec),
                ATTR_CLOCK_WEEKDAY: int(self._hysen_device.clock_weekday),
                ATTR_SCHEDULE: str(HYSEN_SCHEDULE_TO_HASS[self._hysen_device.schedule]),
                ATTR_PERIOD1_HOUR: int(self._hysen_device.period1_hour),
                ATTR_PERIOD1_MIN: int(self._hysen_device.period1_min),
                ATTR_PERIOD1_TEMP: float(self._hysen_device.period1_temp),
                ATTR_PERIOD2_HOUR: int(self._hysen_device.period2_hour),
                ATTR_PERIOD2_MIN: int(self._hysen_device.period2_min),
                ATTR_PERIOD2_TEMP: float(self._hysen_device.period2_temp),
                ATTR_PERIOD3_HOUR: int(self._hysen_device.period3_hour),
                ATTR_PERIOD3_MIN: int(self._hysen_device.period3_min),
                ATTR_PERIOD3_TEMP: float(self._hysen_device.period3_temp),
                ATTR_PERIOD4_HOUR: int(self._hysen_device.period4_hour),
                ATTR_PERIOD4_MIN: int(self._hysen_device.period4_min),
                ATTR_PERIOD4_TEMP: float(self._hysen_device.period4_temp),
                ATTR_PERIOD5_HOUR: int(self._hysen_device.period5_hour),
                ATTR_PERIOD5_MIN: int(self._hysen_device.period5_min),
                ATTR_PERIOD5_TEMP: float(self._hysen_device.period5_temp),
                ATTR_PERIOD6_HOUR: int(self._hysen_device.period6_hour),
                ATTR_PERIOD6_MIN: int(self._hysen_device.period6_min),
                ATTR_PERIOD6_TEMP: float(self._hysen_device.period6_temp),
                ATTR_WE_PERIOD1_HOUR: int(self._hysen_device.we_period1_hour),
                ATTR_WE_PERIOD1_MIN: int(self._hysen_device.we_period1_min),
                ATTR_WE_PERIOD1_TEMP: float(self._hysen_device.we_period1_temp),
                ATTR_WE_PERIOD6_HOUR: int(self._hysen_device.we_period6_hour),
                ATTR_WE_PERIOD6_MIN: int(self._hysen_device.we_period6_min),
                ATTR_WE_PERIOD6_TEMP: float(self._hysen_device.we_period6_temp),
            })
        return attr

    @property
    def temperature_unit(self):
        """Returns the unit of measurement which this thermostat uses."""
        return TEMP_CELSIUS

    @property
    def current_operation(self):
        """Return the current operation mode."""
        if (self.is_on):
            return HYSEN_MODE_TO_HASS[self._hysen_device.operation_mode]
        else:
            return STATE_IDLE

    @property
    def operation_list(self):
        """Returns the list of available operation modes."""
        if (self.current_operation == STATE_IDLE):
            return [HYSEN_MODE_TO_HASS[self._hysen_device.operation_mode], STATE_IDLE]
        else:
            return OPERATION_MODES

    @property
    def current_temperature(self):
        """Returns the sensor temperature."""
        if HYSEN_SENSOR_TO_HASS[self._hysen_device.sensor] == STATE_SENSOR_EXTERNAL:
            return self._hysen_device.external_temp
        else:
            return self._hysen_device.room_temp

    @property
    def target_temperature(self):
        """Returns the target temperature."""
        if (self.current_operation != STATE_IDLE):
            return self._hysen_device.target_temp
        else:
            return None
   
    @property
    def target_temperature_step(self):
        """Returns the supported step of target temperature."""
        return PRECISION_HALVES

    @property
    def is_on(self):
        """Return true if device is on."""
        return self._hysen_device.power_state

    @property
    def supported_features(self):
        """Returns the list of supported features."""
        return SUPPORT_ON_OFF | SUPPORT_OPERATION_MODE | SUPPORT_TARGET_TEMPERATURE

    @property
    def min_temp(self):
        """Returns the minimum supported temperature."""
        return self._hysen_device.min_temp

    @property
    def max_temp(self):
        """Returns the maximum supported temperature."""
        return self._hysen_device.max_temp

    async def async_set_temperature(self, target_temp = None, **kwargs):
        """Set new target temperature."""
        if target_temp == None:
            target_temp = float(kwargs.get(ATTR_TEMPERATURE))
#        _LOGGER.error("[%s] target temp %s", 
#                self._host, 
#                target_temp)
        await self._try_command(
            "Error in set_temperature", 
            self._hysen_device.set_target_temp, 
            target_temp)

    async def async_set_external_limit_temperature(self, external_limit_temp):
        """Set external limit temperature."""
        await self._try_command(
            "Error in async_set_external_limit_temperature", 
            self._hysen_device.set_external_limit_temp, 
            external_limit_temp)
        
    async def async_set_operation_mode(self, operation_mode):
        """Set operation mode."""
        operation_mode = operation_mode.lower()
        if operation_mode not in OPERATION_MODES:
            _LOGGER.error("[%s] Error in async_set_operation_mode. Unknown operation mode \'%s\'.", 
                self._host,
                operation_mode)
            return
        if (operation_mode != self.current_operation):
            if (self.is_on):
                if (operation_mode != STATE_IDLE):
                    if (self.current_operation == STATE_AUTO):
                        if (HASS_MANUAL_OVER_AUTO_TO_HYSEN[self._hysen_device.manual_over_auto] == True):
                            operation_mode = STATE_AUTO
                        else:
#                            _LOGGER.error("[%s] manual target temp %s", 
#                                    self._host, 
#                                    self._hysen_device.manual_target_temp)
                            await self.async_set_temperature(self._hysen_device.manual_target_temp)
                    await self._try_command(
                        "Error in set_operation_mode", 
                                                            
                                                              
                                    
                                               
                        self._hysen_device.set_operation_mode, 
                        HASS_MODE_TO_HYSEN[operation_mode])
                else:
                    await self.async_turn_off()
            else:
                await self.async_turn_on()

    async def async_turn_on(self):
        """Turn device on."""
        await self._try_command(
            "Error in turn_on", 
            self._hysen_device.set_power, 
            HASS_POWER_STATE_TO_HYSEN[True])

    async def async_turn_off(self):
        """Turn device off."""
        await self._try_command(
            "Error in turn_off", 
            self._hysen_device.set_power, 
            HASS_POWER_STATE_TO_HYSEN[False])

    async def async_set_key_lock(self, key_lock):
        """Set key lock 0 = Unlocked, 1 = Locked"""
        if key_lock.lower() not in KEY_LOCK_MODES:
            _LOGGER.error("[%s] Error in async_set_key_lock. Unknown key_lock \'%s\'.", 
                self._host,
                key_lock)
            return
        await self._try_command(
            "Error in set_remote_lock", 
            self._hysen_device.set_remote_lock, 
            HASS_KEY_LOCK_TO_HYSEN[key_lock.lower()])

    async def async_set_sensor(self, sensor):
        """Set sensor type"""
        await self._try_command(
            "Error in set_sensor", 
            self._hysen_device.set_sensor, 
            HASS_SENSOR_TO_HYSEN[sensor.lower()])

    async def async_set_hysteresis(self, hysteresis):
        """Set hysteresis"""
        await self._try_command(
            "Error in set_hysteresis", 
            self._hysen_device.set_hysteresis, 
            hysteresis)

    async def async_set_heating_max_temp(self, max_temp):
        """Set heating upper limit."""
        await self._try_command(
            "Error in set_max_temp", 
            self._hysen_device.set_max_temp, 
            max_temp)

    async def async_set_heating_min_temp(self, min_temp):
        """Set heating lower limit."""
        await self._try_command(
            "Error in set_min_temp", 
            self._hysen_device.set_min_temp, 
            min_temp)

    async def async_set_calibration(self, calibration):
        """Set temperature calibration. Range -5~+5 degree Celsius in 0.5 degree Celsius step."""
        await self._try_command(
            "Error in set_calibration", 
            self._hysen_device.set_calibration, 
            calibration)

    async def async_set_frost_protection(self, frost_protection):
        """Set frost_protection 0 = Off, 1 = When power off keeps the room temp between 5 to 7 degree."""
        await self._try_command(
            "Error in set_frost_protection", 
            self._hysen_device.set_frost_protection, 
            HASS_FROST_PROTECTION_TO_HYSEN[frost_protection])

    async def async_set_poweron(self, poweron):
        """Set poweron 0 = Off, 1 = On."""
        await self._try_command(
            "Error in set_poweron", 
            self._hysen_device.set_poweron, 
            HASS_POWERON_TO_HYSEN[poweron])

    async def async_set_time_now(self):
        """Set device time to system time."""
        clock_weekday = int(dt_util.as_local(dt_util.now()).strftime('%w'))
        if clock_weekday == 0:
            clock_weekday = 7
        clock_hour = int(dt_util.as_local(dt_util.now()).strftime('%H'))
        clock_min = int(dt_util.as_local(dt_util.now()).strftime('%M'))
        clock_sec = int(dt_util.as_local(dt_util.now()).strftime('%S'))
        await self._try_command(
            "Error in set_time", 
            self._hysen_device.set_time, 
            clock_hour, 
            clock_min, 
            clock_sec, 
            clock_weekday)

    async def async_set_schedule(self, schedule):
        """Set week schedule 1 = 1234567 2 = 12345,6 3 = 12345,67."""
        if schedule.lower() not in SCHEDULE_MODES:
            _LOGGER.error("[%s] Error in async_set_schedule. Unknown schedule mode \'%s\'.", 
                self._host,
                schedule)
            return
        await self._try_command(
            "Error in set_weekly_schedule", 
            self._hysen_device.set_weekly_schedule, 
            HASS_SCHEDULE_TO_HYSEN[schedule.lower()])

    async def async_set_period1(self, hour = None, min = None, temp = None):
        """Set daily period 1."""
        await self._try_command(
            "Error in set_period1", 
            self._hysen_device.set_period1, 
            hour, 
            min, 
            temp)

    async def async_set_period2(self, hour = None, min = None, temp = None):
        """Set daily period 2."""
        await self._try_command(
            "Error in set_period2", 
            self._hysen_device.set_period2, 
            hour, 
            min, 
            temp)

    async def async_set_period3(self, hour = None, min = None, temp = None):
        """Set daily period 3."""
        await self._try_command(
            "Error in set_period3", 
            self._hysen_device.set_period3, 
            hour, 
            min, 
            temp)

    async def async_set_period4(self, hour = None, min = None, temp = None):
        """Set daily period 4."""
        await self._try_command(
            "Error in set_period4", 
            self._hysen_device.set_period4, 
            hour, 
            min, 
            temp)

    async def async_set_period5(self, hour = None, min = None, temp = None):
        """Set daily period 5."""
        await self._try_command(
            "Error in set_period5", 
            self._hysen_device.set_period5, 
            hour, 
            min, 
            temp)

    async def async_set_period6(self, hour = None, min = None, temp = None):
        """Set daily period 6."""
        await self._try_command(
            "Error in set_period6", 
            self._hysen_device.set_period6, 
            hour, 
            min, 
            temp)

    async def async_set_we_period1(self, hour = None, min = None,  temp = None):
        """Set daily weekend period 1."""
        await self._try_command(
            "Error in set_we_period1", 
            self._hysen_device.set_we_period1, 
             hour, 
             min, 
             temp)

    async def async_set_we_period6(self,  hour = None,  min = None,  temp = None):
        """Set daily weekend period 6."""
        await self._try_command(
            "Error in set_we_period6", 
            self._hysen_device.set_we_period6, 
             hour, 
             min, 
             temp)

    async def async_authenticate_device(self):
        """Connect to device ."""
        try:
            _authenticated = await self.hass.async_add_executor_job(self._hysen_device.auth)
            if _authenticated:
                _LOGGER.debug("[%s] Device authenticated.", self._host)
            else:
                _LOGGER.debug("[%s] Device not authenticated.", self._host)
        except Exception as exc:
            _LOGGER.error("[%s] Device authentication error: %s", self._host, exc)
            _authenticated = False
        return _authenticated

    async def async_get_device_status(self):
        """Get device status."""
        await self._try_command(
            "Error in get_device_status", 
            self._hysen_device.get_device_status)

    async def _try_command(self, mask_error, func, *args, **kwargs):
        """Calls a device command and handle error messages."""
        self._device_available = True
        try:
            await self.hass.async_add_executor_job(partial(func, *args, **kwargs))
        except socket.timeout as timeout_error:
            _LOGGER.error("[%s] %s: %s", self._host, mask_error, timeout_error)
            self._device_available = False
        except Exception as exc:
            _LOGGER.error("[%s] %s: %s", self._host, mask_error, exc)
            self._device_available = False

    async def async_update(self):
        """Get the latest state from the device."""
        if self._device_authenticated is False:
            self._device_authenticated = await self.async_authenticate_device()
            if self._device_authenticated is False:
                await self.async_get_device_status()
            if self._device_available:
                self._device_authenticated = True
        if self._device_authenticated:
            await self.async_get_device_status()
            # Some devices don't have battery backup. Make sure the time is right.
            _weekday = int(dt_util.as_local(dt_util.now()).strftime('%w'))
            if self._device_available:
                if _weekday == 0:
                    _weekday = 7
                if (self._hysen_device.clock_weekday != _weekday) or \
                   (self._hysen_device.clock_hour != int(dt_util.as_local(dt_util.now()).strftime('%H'))) or \
                   (self._hysen_device.clock_min != int(dt_util.as_local(dt_util.now()).strftime('%M'))):
                    await self.async_set_time_now()
     
