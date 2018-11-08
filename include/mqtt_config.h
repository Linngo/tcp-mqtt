#ifndef __MQTT_CONFIG_H__
#define __MQTT_CONFIG_H__

#define CFG_HOLDER	0x00FF55B3	/* Change this value to load default configurations */
#define CFG_LOCATION	0x79	/* Please don't change or if you know what you doing */
#define MQTT_SSL_ENABLE

typedef enum{
  NO_TLS = 0,                       // 0: disable SSL/TLS, there must be no certificate verify between MQTT server and ESP8266
  TLS_WITHOUT_AUTHENTICATION = 1,   // 1: enable SSL/TLS, but there is no a certificate verify
  ONE_WAY_ANTHENTICATION = 2,       // 2: enable SSL/TLS, ESP8266 would verify the SSL server certificate at the same time
  TWO_WAY_ANTHENTICATION = 3,       // 3: enable SSL/TLS, ESP8266 would verify the SSL server certificate and SSL server would verify ESP8266 certificate
}TLS_LEVEL;
/*DEFAULT CONFIGURATIONS*/

#define CA_CERT_FLASH_ADDRESS 0x77              // CA certificate address in flash to read, 0x77 means address 0x77000
#define CLIENT_CERT_FLASH_ADDRESS 0x78          // client certificate and private key address in flash to read, 0x78 means address 0x78000

#define MQTT_HOST			"order.mqtt.iot.bj.baidubce.com"//"180.149.142.204"//
#define MQTT_PORT			1883
#define MQTT_BUF_SIZE		1500
#define MQTT_KEEPALIVE		60	 /*second*/

#define MQTT_CLIENT_ID		"Nyear_%08X"
#define MQTT_USER			"order/printer"
#define MQTT_PASS			"1TN0FRAa+RSSP14L0cWqxeS/CDjbytF/GV43V8keozc="

#define Subscribe_topic		"ordertopic/device/"
#define Publish_topic		"ordertopic/confirm/"
#define PrintStr(R)			#R
#define STR(R) 				PrintStr(R)

#define STA_SSID ""
#define STA_PASS ""
#define STA_TYPE AUTH_WPA2_PSK

#define MQTT_RECONNECT_TIMEOUT 	5	/*second*/

#define DEFAULT_SECURITY	0//TLS_WITHOUT_AUTHENTICATION
#define QUEUE_BUFFER_SIZE		 	2048

//#define PROTOCOL_NAMEv31	/*MQTT version 3.1 compatible with Mosquitto v0.15*/
#define PROTOCOL_NAMEv311			/*MQTT version 3.11 compatible with https://eclipse.org/paho/clients/testing/*/

#endif // __MQTT_CONFIG_H__
