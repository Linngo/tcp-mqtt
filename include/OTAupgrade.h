/*
 * OTAupgrade.h
 *
 *  Created on: 2018Äê1ÔÂ23ÈÕ
 *      Author: nyear
 */

#ifndef ESP_MQTT_PROJ_INCLUDE_OTAUPGRADE_H_
#define ESP_MQTT_PROJ_INCLUDE_OTAUPGRADE_H_

#include "os_type.h"
#include "mqtt.h"

MQTT_Client mqttClient;
extern bool iscommand;
void ICACHE_FLASH_ATTR webserver_recv(void *arg, char *pusrdata, unsigned short length);

void outputdata(void *arg);
void ICACHE_FLASH_ATTR Queueinit(uint32 buf_size);
uint16_t ICACHE_FLASH_ATTR getqueuelens(void);

#endif /* ESP_MQTT_PROJ_INCLUDE_OTAUPGRADE_H_ */
