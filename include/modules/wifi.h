/*
 * wifi.h
 *
 *  Created on: Dec 30, 2014
 *      Author: Minh
 */

#ifndef USER_WIFI_H_
#define USER_WIFI_H_
#include "os_type.h"
extern bool ModeAP;

typedef void (*WifiCallback)(uint8_t);
void ICACHE_FLASH_ATTR WIFI_Connect(uint8_t* ssid, uint8_t* pass);
void ICACHE_FLASH_ATTR APtoNet(void);
void ICACHE_FLASH_ATTR WIFI_Init(void) ;
void ICACHE_FLASH_ATTR Inter213_InitTCP(uint32_t Local_port) ;
//void ICACHE_FLASH_ATTR DHCP_Discon(void *arg);
void ICACHE_FLASH_ATTR wifi_check_ip(void *arg);
//void timer_to_send(void);


#endif /* USER_WIFI_H_ */
