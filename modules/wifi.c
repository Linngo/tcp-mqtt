/*
 * wifi.c
 *
 *  Created on: Dec 30, 2014
 *      Author: Wu
 */
#include "wifi.h"
#include "user_interface.h"
#include "osapi.h"
#include "espconn.h"
#include "os_type.h"
#include "mem.h"
#include "mqtt_msg.h"
#include "debug.h"
#include "user_config.h"
#include "config.h"
#include "cJSON.h"
#include "espconn.h"//TCP连接需要的头文件
#include "driver/uart.h"
#include "user_webserver.h"
#include "OTAupgrade.h"

static ETSTimer WiFiLinker;
static ETSTimer Discon;
static ETSTimer SendUart;

WifiCallback wifiCb = NULL;
static uint8_t wifiStatus = STATION_IDLE, lastWifiStatus = STATION_IDLE;

struct espconn user_tcp_espconn;
struct espconn user_tcp_9100;

#if multi_client_EN
//static remot_info *Premot = NULL;
recon_info RemotBuf[Client_Num];
static uint8 linkcnt=0;
uint8 i;
#endif

#define delay 50     //230400Baud
//#define delay 125  //115200Baud
volatile bool stopsend = false;

static bool isConnected = false;
bool ModeAP = false;
static uint8 last = 0x00;

void ICACHE_FLASH_ATTR timer_to_send(void *arg){
	struct espconn *pesp_conn;
	if(arg == NULL)
		pesp_conn = &user_tcp_espconn;
	os_timer_disarm(&SendUart);
	os_timer_setfn(&SendUart, (os_timer_func_t *) outputdata, pesp_conn);
	os_timer_arm(&SendUart, delay, true); //启动定时器，单位：毫秒
}

LOCAL void Uart_tcpcb(uint8 client,const char* data, int data_length)
{
//	uint32 time;
	if(last != *data && data_length == 1){
		switch(*data){
		case 0x00:	if(last & 0x06){
						stopsend = false;
						os_delay_us(60000);
						os_delay_us(60000);
						timer_to_send(NULL);
					}
					break;
		case 0x08:  if(last & 0x06){
						stopsend = false;
						os_delay_us(60000);
						os_delay_us(60000);
						timer_to_send(NULL);
					}
					break;
		default:	//if((*data & 0x04)||(*data & 0x02)||(*data & 0x01)) 0x07
			        if(*data & 0x06){
//			        	time = system_get_time();
			        	stopsend = true;
						os_timer_disarm(&SendUart);
			        }
					break;
		}
		if((last & 0x01)&&(!(*data & 0x01))){
			os_printf("---add paper---\r\n");
		}
		if((*data & 0x01)&&(!(last & 0x01))){
			os_printf("---No paper---\r\n");
		}
		if((*data & 0x04)&&(!(last & 0x04))){
			os_printf("---Low cache---\r\n");
//			os_printf("---------time:%3d.%3d \r\n",time/1000000,(time/1000)%1000);
		}
		last = *data;
	}
//	uint32 time = system_get_time();
//	os_printf("---uarttime--- time:%3d.%3d\r\n",time/1000000,(time/1000)%1000);
	if(isConnected){
		for(i = 0;i<Client_Num;i++)
		{
			if(RemotBuf[i].local_port == 8266)
			{
				user_tcp_espconn.proto.tcp->remote_port = RemotBuf[i].remote_port;
				os_memcpy(user_tcp_espconn.proto.tcp->remote_ip,RemotBuf[i].remote_ip,4);
				espconn_send(&user_tcp_espconn, (char*)data, data_length);
				isConnected = false;
			}
		}
	}
}


void ICACHE_FLASH_ATTR wifi_check_ip(void *arg)
{
	struct ip_info ipConfig;
//	static uint8 data[100];
	static uint8 count = 0;

	os_timer_disarm(&WiFiLinker);
	wifi_get_ip_info(STATION_IF, &ipConfig);
	wifiStatus = wifi_station_get_connect_status();
	if (wifiStatus == STATION_GOT_IP && ipConfig.ip.addr != 0)
	{
/*		if(ModeAP==Configuration_mode)
		{
			cJSON * Result = cJSON_CreateObject();
			cJSON_AddNumberToObject(Result, "status", 1);
			cJSON_AddStringToObject(Result, "msg", "STATION_CONNECT_SUCCEED");
			char *succeedData = cJSON_Print(Result);
			os_sprintf(data, "%s", succeedData);
			espconn_send((struct espconn *) &user_tcp_espconn, data, strlen(data));
		}
		else
		{
			os_timer_setfn(&WiFiLinker, (os_timer_func_t *)wifi_check_ip, NULL);
			os_timer_arm(&WiFiLinker, 30000, 0);
		}*/
	}
	else
	{
		if(wifi_station_get_connect_status() == STATION_WRONG_PASSWORD)
		{
			wifiStatus = STATION_WRONG_PASSWORD;
			wifi_station_disconnect();

/*			if(ModeAP==Configuration_mode){
				cJSON * Result = cJSON_CreateObject();
				cJSON_AddNumberToObject(Result, "status", 1);
				cJSON_AddStringToObject(Result, "msg", "STATION_WRONG_PASSWORD");
				char *succeedData = cJSON_Print(Result);
				os_sprintf(data, "%s", succeedData);
				espconn_send((struct espconn *) &user_tcp_espconn, data, strlen(data));
			}else*/
			{
				enlarge;
				uart0_sendStr("Wifi wrong password\r\n\r\n\r\n");
				minify;
			//	WIFI_Init();
			//	Inter213_InitTCP(8266);
				if(Smart_flag == 1){
					smartconfig_stop();
					smart_config();
				}
			}
			count = 0;
			INFO("STATION_WRONG_PASSWORD\r\n");
		}
		else if(wifi_station_get_connect_status() == STATION_NO_AP_FOUND)
		{
			//wifi_station_disconnect();
			struct station_config stationConf;
			wifi_station_get_config(&stationConf);
			wifiStatus = STATION_NO_AP_FOUND;
/*			if(ModeAP==Configuration_mode){
				cJSON * Result = cJSON_CreateObject();
				cJSON_AddNumberToObject(Result, "status", 1);
				cJSON_AddStringToObject(Result, "msg", "STATION_NO_AP_FOUND");
				char *succeedData = cJSON_Print(Result);
				os_sprintf(data, "%s", succeedData);
				espconn_send((struct espconn *) &user_tcp_espconn, data, strlen(data));
			}else*/
			{
				enlarge;
				uart0_sendStr("Can not find ssid:");
				uart0_sendStr(stationConf.ssid);
				uart0_sendStr("\r\n\r\n\r\n");
				minify;
			//	WIFI_Init();
			//	Inter213_InitTCP(8266);
				if(Smart_flag == 1){
					smartconfig_stop();
					smart_config();
				}
			}
			count = 0;
			INFO("STATION_NO_AP_FOUND\r\n");
		}
		else if(wifi_station_get_connect_status() == STATION_CONNECT_FAIL)
		{
			wifiStatus = STATION_CONNECT_FAIL;
			INFO("STATION_CONNECT_FAIL\r\n");
			wifi_station_connect();
		}
		else
		{
			INFO("STATION_IDLE\r\n");
			os_timer_setfn(&WiFiLinker, (os_timer_func_t *)wifi_check_ip, NULL);
			os_timer_arm(&WiFiLinker, 2000, 0);
			count++;
			if(count==30&&Server_Mode==TCP_SERVER){
				uart0_sendStr("Failed to get IP\r\n\r\n\r\n");
				os_timer_disarm(&WiFiLinker);
			}
		}

	}
	if(wifiStatus != lastWifiStatus){
		lastWifiStatus = wifiStatus;
		if(wifiCb)
			wifiCb(wifiStatus);
	}
}

void ICACHE_FLASH_ATTR TCP_recv(void *arg, char *pdata, unsigned short len) {
	struct espconn * Recv = (struct espconn *) arg;
//		uart0_tx_buffer(pdata,len);
//		uart0_sendStr("\r\n");
	webserver_recv(Recv,pdata,len);
}
void ICACHE_FLASH_ATTR server_sent(void *arg) {

		//INFO("send succeed\r\n");
		isConnected = true;
}
static bool tcp_link = 2;

static void ICACHE_FLASH_ATTR discon_callback(void *arg){
	os_timer_disarm(&Discon); //取消定时器定时
	uint8 *i = (uint8*)arg;
	isConnected = false;
	if(tcp_link == 0){
		uart0_sendStr("TCP disconnect:");
		uart_tx_one_char(UART0,*i+0x30);
		uart0_sendStr("\r\n");
//		INFO("\r\n********test point********\r\n");
		tcp_link = 2;
	}
}

void ICACHE_FLASH_ATTR server_discon(void *arg) {

	struct espconn *pesp_conn = (struct espconn *)arg;
#if multi_client_EN
	for(i=0;i<Client_Num;i++){
		if(RemotBuf[i].state == 3
				&& os_strncmp(RemotBuf[i].remote_ip,pesp_conn->proto.tcp->remote_ip,4) == 0
				&& RemotBuf[i].remote_port == pesp_conn->proto.tcp->remote_port
				&& RemotBuf[i].local_port == pesp_conn->proto.tcp->local_port){
			RemotBuf[i].state = pesp_conn->state;
			linkcnt--;
			break;
		}
	}
	os_printf("TCP disconnect %d,remote ip:%d.%d.%d.%d:%d to %d\r\n",i,
			pesp_conn->proto.tcp->remote_ip[0],
			pesp_conn->proto.tcp->remote_ip[1],
			pesp_conn->proto.tcp->remote_ip[2],
			pesp_conn->proto.tcp->remote_ip[3],
			pesp_conn->proto.tcp->remote_port,
			pesp_conn->proto.tcp->local_port);
	if(linkcnt == 0)
	{
		os_timer_disarm(&Discon); //取消定时器定时
		os_timer_setfn(&Discon, (os_timer_func_t *) discon_callback,&i); //设置定时器回调函数
		os_timer_arm(&Discon, 1000, false); //启动定时器，单位：毫秒
	}
#endif
	tcp_link = 0;
}

void ICACHE_FLASH_ATTR server_recon(void *arg, sint8 err) //连接发生异常断开时的回调函数，可以在回调函数中进行重连
{
    struct espconn *pesp_conn = arg;
	for(i=0;i<Client_Num;i++){
		if(RemotBuf[i].state == 3
				&& os_strncmp(RemotBuf[i].remote_ip,pesp_conn->proto.tcp->remote_ip,4) == 0
				&& RemotBuf[i].remote_port == pesp_conn->proto.tcp->remote_port
				&& RemotBuf[i].local_port == pesp_conn->proto.tcp->local_port){
			RemotBuf[i].state = pesp_conn->state;
			linkcnt--;
			break;
		}
	}
    os_printf("webserver's %d.%d.%d.%d:%d err %d reconnect %d\n", pesp_conn->proto.tcp->remote_ip[0],
    		pesp_conn->proto.tcp->remote_ip[1],pesp_conn->proto.tcp->remote_ip[2],
    		pesp_conn->proto.tcp->remote_ip[3],pesp_conn->proto.tcp->remote_port, err,
			pesp_conn->proto.tcp->local_port);
}

void ICACHE_FLASH_ATTR DHCP_Discon(void *arg)
{
	struct espconn *pesp_conn = arg;
	espconn_disconnect(pesp_conn);
}

void ICACHE_FLASH_ATTR server_listen(void *arg) //注册 TCP 连接成功建立后的回调函数
{
	struct espconn *pespconn = (struct espconn *)arg;

	espconn_regist_recvcb(pespconn, TCP_recv); //接收
	espconn_regist_sentcb(pespconn, server_sent); //发送
	espconn_regist_reconcb(pespconn, server_recon); //注册 TCP 连接发生异常断开时的回调函数，可以在回调函数中进行重连
	espconn_regist_disconcb(pespconn, server_discon); //断开

#if multi_client_EN
	//if (espconn_get_connection_info(pespconn,&Premot,0) == ESPCONN_OK)
	{
		for(i=0;i<Client_Num;i++){
			if(RemotBuf[i].state != 3){
				//os_memcpy(&RemotBuf[i],&Premot[pespconn->link_cnt-1],sizeof(remot_info));
				RemotBuf[i].state = pespconn->state;
				RemotBuf[i].remote_port = pespconn->proto.tcp->remote_port;
				os_memcpy(RemotBuf[i].remote_ip,pespconn->proto.tcp->remote_ip,4);
				RemotBuf[i].local_port = pespconn->proto.tcp->local_port;
				linkcnt++;
				break;
			}
		}

		os_printf("TCP connect %d,remote ip:%d.%d.%d.%d:%d,to %d\r\n",i,
				pespconn->proto.tcp->remote_ip[0],
				pespconn->proto.tcp->remote_ip[1],
				pespconn->proto.tcp->remote_ip[2],
				pespconn->proto.tcp->remote_ip[3],
				pespconn->proto.tcp->remote_port,
				pespconn->proto.tcp->local_port);
	}
	isConnected = true;
	if(tcp_link == 2)
	{
		uart0_sendStr("TCP connect:");
		uart_tx_one_char(UART0, i+0x30);
		uart0_sendStr("\r\n");
	}
#else
	INFO("TCP connect\r\n");
	uart0_sendStr("TCP connect\r\n");
#endif
	tcp_link = 1;
#if Queue_en
	stopsend = false;
	timer_to_send(NULL);
#endif
}

void ICACHE_FLASH_ATTR Inter213_InitTCP(uint32_t Local_port)
{
	if(Local_port == 8266)
	{
		user_tcp_espconn.proto.tcp = (esp_tcp *) os_zalloc(sizeof(esp_tcp)); //分配空间
		user_tcp_espconn.type = ESPCONN_TCP; //设置类型为TCP协议
		user_tcp_espconn.proto.tcp->local_port = Local_port; //本地端口
		user_tcp_espconn.state = ESPCONN_NONE;
		//注册连接成功回调函数和重新连接回调函数
		espconn_regist_connectcb(&user_tcp_espconn, server_listen); //注册 TCP 连接成功建立后的回调函数

		espconn_accept(&user_tcp_espconn); //创建 TCP server，建立侦听
		espconn_regist_time(&user_tcp_espconn, 180, 0); //设置超时断开时间 单位：秒，最大值：7200 秒

		espconn_tcp_set_max_con_allow(&user_tcp_espconn,1);
	}else
	{
		user_tcp_9100.proto.tcp = (esp_tcp *) os_zalloc(sizeof(esp_tcp)); //分配空间
		user_tcp_9100.type = ESPCONN_TCP; //设置类型为TCP协议
		user_tcp_9100.proto.tcp->local_port = Local_port; //本地端口
		user_tcp_9100.state = ESPCONN_NONE;
		//注册连接成功回调函数和重新连接回调函数
		espconn_regist_connectcb(&user_tcp_9100, server_listen); //注册 TCP 连接成功建立后的回调函数

		espconn_accept(&user_tcp_9100); //创建 TCP server，建立侦听
		espconn_regist_time(&user_tcp_9100, 180, 0); //设置超时断开时间 单位：秒，最大值：7200 秒

		espconn_tcp_set_max_con_allow(&user_tcp_9100,1);
	}
}

void ICACHE_FLASH_ATTR print_apmode(void){
	enlarge;
	uart0_sendStr("AP:");
	uart0_sendStr(sysCfg.device_id);
	uart0_sendStr("\r\n\r\n\r\n");
	minify;
}

void ICACHE_FLASH_ATTR WIFI_Init(void)
{
	ModeAP=Configuration_mode;
	struct softap_config apConfig;
	wifi_set_opmode_current(STATIONAP_MODE);
	apConfig.ssid_len = 14;						//设置ssid长度
	os_strcpy(apConfig.ssid, sysCfg.device_id);
	//os_strcpy(apConfig.ssid, "测试wifi热点");	    //设置ssid名字
	os_strcpy(apConfig.password, "12345678");	//设置密码12345678
	apConfig.authmode = AUTH_WPA_WPA2_PSK;      /*设置加密模式 AUTH_OPEN,AUTH_WEP,AUTH_WPA_PSK,
												  AUTH_WPA2_PSK,AUTH_WPA_WPA2_PSK,AUTH_MAX*/
	apConfig.beacon_interval = 100;            //信标间隔时槽100 ~ 60000 ms
	apConfig.channel = 6;                      //通道号1 ~ 13
	apConfig.max_connection = 1;               //最大连接数
	apConfig.ssid_hidden = 0;                  //隐藏SSID

	wifi_softap_set_config_current(&apConfig);
	os_timer_disarm(&WiFiLinker);
	INFO("AP mode\r\n");

	os_timer_disarm(&Discon);
	os_timer_setfn(&Discon, (os_timer_func_t *)print_apmode, NULL);
	os_timer_arm(&Discon, 2000, 0);

}

void ICACHE_FLASH_ATTR wifi_connect_2s(void)
{
	wifi_station_disconnect();
	wifi_station_connect();
	wifi_check_ip(NULL);
}
void ICACHE_FLASH_ATTR WIFI_Connect(uint8_t* ssid, uint8_t* pass)
{
	struct station_config stationConf;

	INFO("WIFI_INIT\r\n");

//	INFO(" wifiStationConnect name:%s \r\n", ssid);
//	INFO(" wifiStationConnect psw :%s \r\n", pass);

//	wifi_set_opmode(STATION_MODE);

	os_memset(&stationConf, 0, sizeof(struct station_config));

	os_sprintf(stationConf.ssid, "%s", ssid);
	os_sprintf(stationConf.password, "%s", pass);

	wifi_station_set_config(&stationConf);

//	wifi_station_set_auto_connect(FALSE);
	os_timer_disarm(&WiFiLinker);
	os_timer_setfn(&WiFiLinker, (os_timer_func_t *)wifi_connect_2s, NULL);
	os_timer_arm(&WiFiLinker, 1000, 0);
}

void ICACHE_FLASH_ATTR APtoNet(void)
{
	wifi_station_set_auto_connect(TRUE);
	wifi_set_sleep_type(NONE_SLEEP_T);                     //set none sleep mode

	espconn_tcp_set_max_con(Client_Num);

	TCP_Response(Uart_tcpcb);
}
