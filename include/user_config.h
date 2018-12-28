#ifndef __USER_CONFIG_H__
#define __USER_CONFIG_H__

#define USE_OPTIMIZE_PRINTF

#define IOT_VERSION_MAJOR		1U
#define IOT_VERSION_MINOR		1U
#define IOT_VERSION_REVISION	4U


#define EN_boot_wificonfig 0
#define multi_client_EN 1
#define Client_Num 2
#define Queue_en 1
#define Bufnum 10


#define enlarge uart_tx_one_char(UART0, 0x1b);\
				uart_tx_one_char(UART0, 0x61);\
				uart_tx_one_char(UART0, 0x02)

#define minify  uart_tx_one_char(UART0, 0x1b);\
				uart_tx_one_char(UART0, 0x61);\
				uart_tx_one_char(UART0, 0x00)

#endif

