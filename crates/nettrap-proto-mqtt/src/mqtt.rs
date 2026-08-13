/// MQTT packet types (v3.1.1 / v5.0)
pub const MQTT_CONNECT: u8 = 1;
pub const MQTT_CONNACK: u8 = 2;
pub const MQTT_PUBLISH: u8 = 3;
pub const MQTT_PUBACK: u8 = 4;
pub const MQTT_PUBREC: u8 = 5;
pub const MQTT_PUBREL: u8 = 6;
pub const MQTT_PUBCOMP: u8 = 7;
pub const MQTT_SUBSCRIBE: u8 = 8;
pub const MQTT_SUBACK: u8 = 9;
pub const MQTT_UNSUBSCRIBE: u8 = 10;
pub const MQTT_UNSUBACK: u8 = 11;
pub const MQTT_PINGREQ: u8 = 12;
pub const MQTT_PINGRESP: u8 = 13;
pub const MQTT_DISCONNECT: u8 = 14;

/// MQTT CONNACK return codes
pub const CONNACK_ACCEPTED: u8 = 0;
pub const CONNACK_BAD_PROTOCOL: u8 = 1;
pub const CONNACK_ID_REJECTED: u8 = 2;
pub const CONNACK_SERVER_UNAVAILABLE: u8 = 3;
pub const CONNACK_BAD_AUTH: u8 = 4;
pub const CONNACK_NOT_AUTHORIZED: u8 = 5;

/// MQTT session state
#[derive(Debug, Clone, PartialEq, Default)]
pub enum MqttState {
    /// Waiting for CONNECT packet
    #[default]
    WaitingConnect,
    /// Connected and ready for publish/subscribe
    Connected,
    /// Disconnected
    Disconnected,
}
