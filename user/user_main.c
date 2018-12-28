/* main.c -- MQTT client example
*
* Copyright (c) 2014-2015, Tuan PM <tuanpm at live dot com>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* * Redistributions of source code must retain the above copyright notice,
* this list of conditions and the following disclaimer.
* * Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
* * Neither the name of Redis nor the names of its contributors may be used
* to endorse or promote products derived from this software without
* specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/
#include "ets_sys.h"
#include "driver/uart.h"
#include "osapi.h"
#include "mqtt.h"
#include "wifi.h"
#include "config.h"
#include "debug.h"
#include "gpio.h"
#include "user_interface.h"
#include "mem.h"

#include "hal_key.h"
#include "user_devicefind.h"
#include "sntp.h"

#include "smartconfig.h"

#include "OTAupgrade.h"
//#include <iconv.h>

//MQTT_Client mqttClient;
static ETSTimer sntp_timer;
static uint8 mqttstatus = 0;
static bool connect_flag = 0;
static ETSTimer init_timer;

#define GPIO_KEY_NUM                            1
#define KEY_0_IO_MUX                            PERIPHS_IO_MUX_MTMS_U
#define KEY_0_IO_NUM                            14
#define KEY_0_IO_FUNC                           FUNC_GPIO14

LOCAL key_typedef_t * singleKey[GPIO_KEY_NUM];
LOCAL keys_typedef_t keys;


LOCAL void ICACHE_FLASH_ATTR keyLongPress(void) {
	Smart_flag=1;
	smart_config();
}

LOCAL void ICACHE_FLASH_ATTR keyShortPress(void) {
	os_printf(" key short...\r\n");
	if(Smart_flag==1){
		smartconfig_stop();
		Smart_flag=0;
	}
	wifi_station_disconnect();
	WIFI_Init();
	Inter213_InitTCP(8266); //本地端口
}
//按键初始化
LOCAL void ICACHE_FLASH_ATTR keyInit(void) {
	singleKey[0] = keyInitOne(KEY_0_IO_NUM, KEY_0_IO_MUX, KEY_0_IO_FUNC,
			keyLongPress, keyShortPress);
	keys.singleKey = singleKey;
	keyParaInit(&keys);
}

static uint8 orderId[32]={0x00},
			 channel=0x00;

LOCAL void Uart_mqttcb(const char* data, int data_length)
{
	static uint8 lastdata;
	uint8 msg;
	uint8 *Mqttbuf=NULL;
	if(mqttstatus == server_connect){
		if(data_length == 1){
			//{channel: 订单来源,orderId:订单ID,msgCode:打印状态};
			if(lastdata != *data){

				switch(*data){
				case 0x08: msg='5';break;
				//case 0x04: break;
				case 0x02: msg='3';break;
				case 0x01: msg='4';break;
				case 0x00: msg='1';break;
				default: msg = '2';
				}
				Mqttbuf = (uint8*)os_zalloc(100);
				os_sprintf(Mqttbuf,"{channel:%c,orderId:\"%s\",printId:\"%s\",msgCode:%c}",
							Confirmdata.channel,Confirmdata.orderId,sysCfg.device_id,msg);
				MQTT_Publish(&mqttClient, sysCfg.Publish, Mqttbuf, 57+os_strlen(Confirmdata.orderId), 0, 0);
//				INFO("*****publish*2:%s\r\n",Mqttbuf);
				os_free(Mqttbuf);
				lastdata = *data;
				if(*data == 0x00){
					Confirmdata.channel = 0x00;
					Confirmdata.orderId[0] = 0x00;
					orderId[0] = 0x00;
					channel = 0x00;
				}
			}
		}else
			MQTT_Publish(&mqttClient, sysCfg.Publish, data, data_length, 0, 0);
	}
}

void ICACHE_FLASH_ATTR
sntpfn()
{
    uint32 ts = 0;
    static uint8 timeout=0;
    ts = sntp_get_current_timestamp();
    os_printf("current time : %s\n", sntp_get_real_time(ts));
    if (ts == 0) {
        //os_printf("did not get a valid time from sntp server\n");
    	timeout++;
    } else {
            os_timer_disarm(&sntp_timer);
            MQTT_Connect(&mqttClient);
    }
    if(timeout>=15){
    	enlarge;
    	//uart0_sendStr("Time Server connection failed.\n");
    	minify;
    	os_timer_disarm(&sntp_timer);
    	  MQTT_Connect(&mqttClient);
    }
}

void ICACHE_FLASH_ATTR
mqttConnectedCb(uint32_t *args)
{
	MQTT_Client* client = (MQTT_Client*)args;
	uint32 ts = 0;

	Confirmdata.channel = 0x00;
	Confirmdata.orderId[0] = 0x00;
	INFO("MQTT: Connected\r\n");
	if(mqttstatus == mqtt_not_connect)
	{
		os_delay_us(60000);
		os_delay_us(60000);
		os_delay_us(60000);
		enlarge;
		uart0_sendStr("Server connect\r\nID:");
		uart0_sendStr(sysCfg.device_id);
		uart0_sendStr("\r\n");
		ts = sntp_get_current_timestamp();
		uart0_sendStr(sntp_get_real_time(ts));
		uart0_sendStr("\r\n\r\n\r\n");
		minify;
	}
	mqttstatus = server_connect;
	MQTT_Subscribe(client, sysCfg.Subscribe, 0);
//	MQTT_Publish(client, sysCfg.Publish, "hello0", 6, 0, 0);
	timer_to_send();
}

void ICACHE_FLASH_ATTR Server_disconnect(void){
	if(mqttstatus == server_disconnect){
		enlarge;
		uart0_sendStr("Server disconnect\r\n\r\n\r\n");
		minify;
		mqttstatus = mqtt_not_connect;
	}
}

void ICACHE_FLASH_ATTR
mqttDisconnectedCb(uint32_t *args)
{
	MQTT_Client* client = (MQTT_Client*)args;

	mqttstatus = server_disconnect;
	INFO("MQTT: Disconnected\r\n");
//	timecount = system_get_time();
	os_timer_disarm(&init_timer); //取消定时器定时
	os_timer_setfn(&init_timer, (os_timer_func_t *) Server_disconnect,NULL); //设置定时器回调函数
	os_timer_arm(&init_timer, 60000, false); //启动定时器，单位：毫秒
}

void ICACHE_FLASH_ATTR
mqttPublishedCb(uint32_t *args)
{
	MQTT_Client* client = (MQTT_Client*)args;
	INFO("MQTT: Published\r\n");
//	uart0_sendStr("MQTT: Published\r\n");
}

static uint8 lastten[Bufnum][22]={0};
static uint8 num = 0;

void mqttDataCb(uint32_t *args, const char* topic, uint32_t topic_len, const char *data, uint32_t data_len)
{
	char *topicBuf = (char*)os_zalloc(topic_len+1),
			*dataBuf = (char*)os_zalloc(data_len+1);

	uint8 *p = NULL,
		   i = 0;
	static bool repeatflag=false;

	MQTT_Client* client = (MQTT_Client*)args;

	os_memcpy(topicBuf, topic, topic_len);
	topicBuf[topic_len] = 0;

	os_memcpy(dataBuf, data, data_len);
	dataBuf[data_len] = 0;

	INFO("Receive topic: %s,len:%d \r\n", topicBuf,data_len);

	p = dataBuf;
//	INFO("%s\r\n",data);
	if(Data_analyze(dataBuf,data_len)){
		if(*p=='|'&& *(p+2)=='|'){
			Confirmdata.channel = *(p+1);
			p=p+3;
			while(*p!='|'&&i<31){
				Confirmdata.orderId[i++]=*p++;
			}
			if(i==31 || i==0){
				Confirmdata.orderId[0] = 0;
				goto OUT;
			}
			else
			{
				p++;
				Confirmdata.orderId[i] = 0;
				INFO("channel: %c,Id:%s last:%c,%s\r\n", Confirmdata.channel,Confirmdata.orderId,channel,orderId);

				uint8 *rev = (uint8*)os_zalloc(22);
				os_sprintf(rev,"%c,%s",Confirmdata.channel,Confirmdata.orderId);

				INFO("------%s\r\n",os_strstr(lastten[0],rev)==0?"正常":"重复");
				if(os_strstr(lastten[0],rev) == 0||*p == '1')
				{
					os_strcpy(lastten[num],rev);
					strncat(lastten[num],"********************",21-os_strlen(lastten[num]));
					lastten[num][21] = '*';
					num++;

					if((os_strcmp(orderId,Confirmdata.orderId)!=0||channel != Confirmdata.channel)
							&& Confirmdata.channel!=0x00 && channel != 0x00){//os_strlen(Confirmdata.orderId)>0 &&
						uint8 *Mqttbuf = (uint8*)os_zalloc(100);
						os_sprintf(Mqttbuf,"{channel:%c,orderId:\"%s\",printId:\"%s\",msgCode:1}",channel,orderId,sysCfg.device_id);
						MQTT_Publish(&mqttClient, sysCfg.Publish, Mqttbuf, 57+os_strlen(Confirmdata.orderId), 0, 0);
	//					INFO("*****publish*1:%s\r\n",Mqttbuf);
						os_free(Mqttbuf);
					}
					channel = Confirmdata.channel;
					os_strcpy(orderId,Confirmdata.orderId);

					if(data_len>32)
					webserver_recv(NULL,dataBuf+32,data_len-32);
					repeatflag = false;
				}else
					repeatflag = true;

				if(num>(Bufnum-1)) {num=0;lastten[Bufnum-1][21] = 0x00;}
//				INFO("%s\r\n",lastten[0]);
				os_free(rev);
			}
		}else{
OUT:		if(topic_len||(repeatflag==0&&topic_len==0))
				webserver_recv(NULL,dataBuf,data_len);
			if(topic_len)
				repeatflag = false;
		}
	}

	os_free(topicBuf);
	os_free(dataBuf);
}


/******************************************************************************
 * FunctionName : user_rf_cal_sector_set
 * Description  : SDK just reversed 4 sectors, used for rf init data and paramters.
 *                We add this function to force users to set rf cal sector, since
 *                we don't know which sector is free in user's application.
 *                sector map for last several sectors : ABCCC
 *                A : rf cal
 *                B : rf init data
 *                C : sdk parameters
 * Parameters   : none
 * Returns      : rf cal sector
 *******************************************************************************/
uint32 ICACHE_FLASH_ATTR
user_rf_cal_sector_set(void)
{
    enum flash_size_map size_map = system_get_flash_size_map();
    uint32 rf_cal_sec = 0;

    switch (size_map) {
        case FLASH_SIZE_4M_MAP_256_256:
            rf_cal_sec = 128 - 5;
            break;

        case FLASH_SIZE_8M_MAP_512_512:
            rf_cal_sec = 256 - 5;
            break;

        case FLASH_SIZE_16M_MAP_512_512:
        case FLASH_SIZE_16M_MAP_1024_1024:
            rf_cal_sec = 512 - 5;
            break;

        case FLASH_SIZE_32M_MAP_512_512:
        case FLASH_SIZE_32M_MAP_1024_1024:
            rf_cal_sec = 1024 - 5;
            break;

        case FLASH_SIZE_64M_MAP_1024_1024:
            rf_cal_sec = 2048 - 5;
            break;
        case FLASH_SIZE_128M_MAP_1024_1024:
            rf_cal_sec = 4096 - 5;
            break;
        default:
            rf_cal_sec = 0;
            break;
    }

    return rf_cal_sec;
}

void ICACHE_FLASH_ATTR print_info()
{
	struct rst_info *rtc_info = system_get_rst_info();

	os_printf("\r\nreset reason: %x\r\n", rtc_info->reason);
	if (rtc_info->reason == REASON_WDT_RST ||
		rtc_info->reason == REASON_EXCEPTION_RST ||
		rtc_info->reason == REASON_SOFT_WDT_RST) {
		if (rtc_info->reason == REASON_EXCEPTION_RST) {
			os_printf("Fatal exception (%d):\n", rtc_info->exccause);
		}
		os_printf("epc1=0x%08x, epc2=0x%08x, epc3=0x%08x, excvaddr=0x%08x, depc=0x%08x\n",
				rtc_info->epc1, rtc_info->epc2, rtc_info->epc3, rtc_info->excvaddr, rtc_info->depc);
		uint8 *Buf = (uint8*)os_zalloc(40);
		os_sprintf(Buf,"reset reason: %x\r\n epc1=0x%08x\r\n",rtc_info->reason,rtc_info->epc1);
		uart0_sendStr(Buf);
		os_free(Buf);
	}
	INFO("\r\n\r\n[INFO] BOOTUP...\r\n");
	INFO("[INFO] Version V%d.%d.%d\r\n",IOT_VERSION_MAJOR,IOT_VERSION_MINOR,IOT_VERSION_REVISION);
	INFO("[INFO] SDK: %s\r\n", system_get_sdk_version());
	INFO("[INFO] Chip ID: %s\r\n", sysCfg.device_id);
	INFO("[INFO] Memory info:\r\n");
	system_print_meminfo();

	INFO("\r\n[INFO] BOOT ADDRESS:%X\r\n",system_get_userbin_addr());
}
/**********************************************************************************
 * 测试转码
 * *******************************************************************************/
/*int u2g(char *inbuf, size_t inlen,char *outbuf, size_t outlen) {
    iconv_t cd;
    char **pin = &inbuf;
    char **pout = &outbuf;

    cd = iconv_open("GB2312","UTF-8");
    if (cd==0)
            return -1;
    memset(outbuf,0,outlen);
    if (iconv(cd,(const char**)pin,&inlen,pout,&outlen) == -1)
            return -1;
    iconv_close(cd);

    return 0;
}*/

void wifi_handle_event_cb(System_Event_t *evt)
{
//	os_printf("event %x\n", evt->event);
	switch (evt->event) {
	case EVENT_STAMODE_CONNECTED:
		if(connect_flag == 0)
		{
			wifi_check_ip(NULL);
			enlarge;
			uint8 *buf = (uint8*)os_zalloc(evt->event_info.connected.ssid_len+23);
//			u2g(evt->event_info.connected.ssid,evt->event_info.connected.ssid_len,buf,evt->event_info.connected.ssid_len);
//			INFO("%s\r\n",buf);
			os_sprintf(buf,"connect to %s\r\n",evt->event_info.connected.ssid);
			uart0_sendStr(buf);
			os_free(buf);
			minify;
		}
		break;
	case EVENT_STAMODE_DISCONNECTED:
		if(connect_flag == 1 && Smart_flag == 0){
			os_printf("Wifi disconnect\r\n");
			wifi_check_ip(NULL);
			connect_flag = 0;
			if(Server_Mode==MQTT_CLIENT)
				MQTT_Disconnect(&mqttClient);
		}

/*		if(Server_Mode==MQTT_CLIENT)
		{
			//MQTT_Disconnect(&mqttClient);
		}
		else if(Server_Mode==TCP_SERVER)
		{

		}*/
		break;
	case EVENT_STAMODE_AUTHMODE_CHANGE:

		break;
	case EVENT_STAMODE_GOT_IP:
		INFO("GET_IP\r\n");
		sntp_init();
/*		if(ModeAP==Configuration_mode){}
		else*/
		{
			enlarge;
			if(Server_Mode==MQTT_CLIENT&&ModeAP==Operating_mode)
			{
				MQTT_InitConnection(&mqttClient, sysCfg.mqtt_host, sysCfg.mqtt_port, sysCfg.security);
				//MQTT_InitConnection(&mqttClient, "mq.tongxinmao.com", 18830, 0);

				MQTT_InitClient(&mqttClient, sysCfg.device_id, sysCfg.mqtt_user, sysCfg.mqtt_pass, sysCfg.mqtt_keepalive, 1);
				//MQTT_InitClient(&mqttClient, sysCfg.device_id, NULL, NULL, 120, 1);

				//MQTT_InitLWT(&mqttClient, "/lwt", "offline", 0, 0);
				MQTT_OnConnected(&mqttClient, mqttConnectedCb);
				MQTT_OnDisconnected(&mqttClient, mqttDisconnectedCb);
				MQTT_OnPublished(&mqttClient, mqttPublishedCb);
				MQTT_OnData(&mqttClient, mqttDataCb);

				MQTT_Response(Uart_mqttcb);

				os_timer_disarm(&sntp_timer);
				os_timer_setfn(&sntp_timer, (os_timer_func_t *)sntpfn, NULL);
				os_timer_arm(&sntp_timer, 1000, 1);//1s
			//	MQTT_Connect(&mqttClient);
			}else
		//	if(Server_Mode==TCP_SERVER)
			{
				if(connect_flag == 0)
				{
					uint8 *Buf = (uint8*)os_zalloc(22);
					os_sprintf(Buf,"ip:" IPSTR,IP2STR(&evt->event_info.got_ip.ip));
					uart0_sendStr(Buf);
					os_free(Buf);
					uart0_sendStr("\r\n\r\n\r\n");
				}
				Inter213_InitTCP(8266);
				Inter213_InitTCP(9100);
			}
			minify;

			connect_flag = 1;
			Smart_flag = 0;
		}
		break;
	case EVENT_SOFTAPMODE_STACONNECTED:

		break;
	case EVENT_SOFTAPMODE_STADISCONNECTED:

		break;
	default:
		break;
	  }
}

void ICACHE_FLASH_ATTR print_smartcfg(void){
	enlarge;
	uart0_sendStr("Smartconfig\r\n\r\n\r\n");
	minify;
}
void ICACHE_FLASH_ATTR print_notcfg(void){
	enlarge;
	uart0_sendStr("Wifi is not configured\r\n");
	minify;
}

void ICACHE_FLASH_ATTR System_init(void)
{
	uart0_sendStr("\r\nopen Uart\r\n");
	os_delay_us(60000);
	//	keyInit();

/*	uint8 *Buf = (uint8*)os_zalloc(22);
	os_sprintf(Buf,"\r\nID: %s\r\n", sysCfg.device_id);
	uart0_sendStr(Buf);
	os_free(Buf);*/

	if(Smart_flag == 0){
		struct station_config stationConf;
		wifi_station_get_config(&stationConf);
	//	INFO("wifi config info %s,%s\r\n",stationConf.ssid,stationConf.password);
		if(stationConf.ssid[0]=='\0'&&stationConf.password[0]=='\0'){

			INFO("Wifi is not configured\r\n");
			os_timer_disarm(&init_timer); //取消定时器定时
			os_timer_setfn(&init_timer, (os_timer_func_t *) print_notcfg,NULL); //设置定时器回调函数
			os_timer_arm(&init_timer, 1500, false); //启动定时器，单位：毫秒

			WIFI_Init();
			Inter213_InitTCP(8266);
			Inter213_InitTCP(9100);
	//		smartconfig_stop();
	//		smart_config();
		}else
		{
			if(Server_Mode == AP_MODE){
				WIFI_Init();
				Inter213_InitTCP(8266);
				Inter213_InitTCP(9100);
			}
			else{
	//			wifi_station_connect();
				os_timer_disarm(&init_timer); //取消定时器定时
				os_timer_setfn(&init_timer, (os_timer_func_t *) wifi_station_connect,NULL); //设置定时器回调函数
				os_timer_arm(&init_timer, 1500, false); //启动定时器，单位：毫秒
				wifi_check_ip(NULL);
			}
		}
	}else{
		os_timer_disarm(&init_timer); //取消定时器定时
		os_timer_setfn(&init_timer, (os_timer_func_t *) print_smartcfg,NULL); //设置定时器回调函数
		os_timer_arm(&init_timer, 1500, false); //启动定时器，单位：毫秒
	}

	APtoNet();
#if Queue_en
//	if(Server_Mode==TCP_SERVER)
	Queueinit(1460*8);
#endif

	user_devicefind_init();
	INFO("\r\nSystem started ...\r\n");
}
#if EN_boot_wificonfig
static void ICACHE_FLASH_ATTR
config_wifi_done(sc_status status, void *pdata)
{
    switch(status) {
        case SC_STATUS_WAIT:
            os_printf("SC_STATUS_WAIT\n");
            break;
        case SC_STATUS_FIND_CHANNEL:
            os_printf("SC_STATUS_FIND_CHANNEL\n");
            break;
        case SC_STATUS_GETTING_SSID_PSWD:
            os_printf("SC_STATUS_GETTING_SSID_PSWD\n");
			sc_type *type = pdata;
            if (*type == SC_TYPE_ESPTOUCH) {
                os_printf("SC_TYPE:SC_TYPE_ESPTOUCH\n");
            } else {
                os_printf("SC_TYPE:SC_TYPE_AIRKISS\n");
            }
            os_timer_disarm(&init_timer); //取消定时器定时
            break;
        case SC_STATUS_LINK:
            os_printf("SC_STATUS_LINK\n");
            struct station_config *sta_conf = pdata;

	        wifi_station_set_config(sta_conf);
	        wifi_station_disconnect();
	        wifi_station_connect();

	        System_init();
            break;
        case SC_STATUS_LINK_OVER:
            os_printf("SC_STATUS_LINK_OVER\n");
            if (pdata != NULL) {
				//SC_TYPE_ESPTOUCH
                uint8 phone_ip[4] = {0};

                os_memcpy(phone_ip, (uint8*)pdata, 4);
                os_printf("Phone ip: %d.%d.%d.%d\n",phone_ip[0],phone_ip[1],phone_ip[2],phone_ip[3]);
            } else {
            	//SC_TYPE_AIRKISS - support airkiss v2.0
		//		airkiss_start_discover();
            }
            smartconfig_stop();
            break;
    }

}
void ICACHE_FLASH_ATTR init_timer_andle(void *arg){
	smartconfig_stop();
	os_timer_disarm(&init_timer); //取消定时器定时
	System_init();
}

static void  config_wifi(void){
	smartconfig_set_type(SC_TYPE_ESPTOUCH); //SC_TYPE_ESPTOUCH,SC_TYPE_AIRKISS,SC_TYPE_ESPTOUCH_AIRKISS
    wifi_set_opmode(STATION_MODE);
    esptouch_set_timeout(30); //15s~255s, offset:45s
    smartconfig_start(config_wifi_done);
}
#endif
/*
void ICACHE_FLASH_ATTR scan_done(void *arg,STATUS status){

     uint8 ssid[33];
      char temp[128];
      struct station_config stationConf;
      if (status == OK)
       {
         struct bss_info *bss_link = (struct bss_info *)arg;
         bss_link = bss_link->next.stqe_next;//ignore first

         while (bss_link != NULL)
         {
           os_memset(ssid, 0, 33);
           if (os_strlen(bss_link->ssid) <= 32)
           {
             os_memcpy(ssid, bss_link->ssid, os_strlen(bss_link->ssid));
           }
           else
           {
             os_memcpy(ssid, bss_link->ssid, 32);
           }
           os_sprintf(temp,"+CWLAP:(%d,\"%s\",%d,\""MACSTR"\",%d)\r\n",
                      bss_link->authmode, ssid, bss_link->rssi,
                      MAC2STR(bss_link->bssid),bss_link->channel);
           os_printf("%s",temp);
           bss_link = bss_link->next.stqe_next;
         }
         System_init();
       }
       else
       {
        os_printf("%s","Error");
       }
}
void to_scan(void)  { wifi_station_scan(NULL,scan_done); }*/

void user_init(void){
	uart_init(BIT_RATE_230400, BIT_RATE_460800);
//	system_uart_swap();
	wifi_station_set_auto_connect(false);

/*
	ip_addr_t adr;
    adr.addr = 0x72727272;
*/
	CFG_Load();
	os_delay_us(60000);
	print_info();

	wifi_station_set_hostname("Nyear_printer");

	if(wifi_get_opmode()!=STATION_MODE)
	{
		wifi_set_opmode(STATION_MODE);
	}
	wifi_set_event_handler_cb(wifi_handle_event_cb);

	sntp_setservername(0, "ntp1.aliyun.com");        // set sntp server after got ip address
	sntp_setservername(1, "cn.ntp.org.cn");
	sntp_setservername(2, "pool.ntp.org");
/*	wifi_station_dhcpc_stop();
	espconn_dns_setserver(1,&adr);
	wifi_station_dhcpc_start();*/
    os_printf("%x,%x\r\n",espconn_dns_getserver(0),espconn_dns_getserver(1));

	spi_flash_read((CFG_LOCATION + 2) * SPI_FLASH_SEC_SIZE,
				  (uint32 *)&Server_Mode, sizeof(Server_Mode));

	if(Server_Mode==MQTT_CLIENT)
	{
		INFO("\r\nMQTT_CLIENT mode\r\n");
	//	uart0_sendStr("MQTT mode\r\n");
	}
	else if(Server_Mode==TCP_SERVER)
	{
		INFO("\r\nTCP_SERVER mode\r\n");
	//	uart0_sendStr("TCP mode\r\n");
	}else if(Server_Mode==AP_MODE)
	{
		INFO("\r\nAP mode\r\n");
	//	uart0_sendStr("AP MODE\r\n");
	}else {
		INFO("\r\nmode err\r\n");
	}

	uart0_sendStr("\r\nclose Uart\r\n");

	os_timer_disarm(&init_timer); //取消定时器定时
	os_timer_setfn(&init_timer, (os_timer_func_t *) System_init,NULL); //设置定时器回调函数
	os_timer_arm(&init_timer, 3500, false); //启动定时器，单位：毫秒
	//os_timer_arm(&init_timer, 15000, false); //启动定时器，单位：毫秒
#if EN_boot_wificonfig
	system_init_done_cb(config_wifi);
	//system_init_done_cb(to_scan);
#endif
}
