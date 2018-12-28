/*
 * OTAupgrade.c
 *
 *  Created on: 2018骞�1鏈�23鏃�
 *      Author: nyear
 */
#include "ets_sys.h"
#include "os_type.h"
#include "osapi.h"
#include "mem.h"
#include "user_interface.h"

#include "espconn.h"
#include "user_webserver.h"
#include "upgrade.h"
#include "user_json.h"
#include "driver/uart.h"
#include "user_config.h"
#include "spi_flash.h"
#include "cJSON.h"
#include "config.h"
#include "sntp.h"
#include "queue.h"
#include "ringbuf.h"

uint8 upgrade_lock = 0;
LOCAL os_timer_t app_upgrade_10s;
LOCAL os_timer_t upgrade_check_timer;

/*
 *   CRC
 * */

#define BUFSIZE     512
#define CRC_BLOCK_SIZE 512
uint16 start_sec;
static unsigned int *crc_table;

#ifdef MEMLEAK_DEBUG
static const char mem_debug_file[] ICACHE_RODATA_ATTR = __FILE__;
#endif


static int init_crc_table(void);
static unsigned int crc32(unsigned int crc, unsigned char * buffer, unsigned int size);

static int ICACHE_FLASH_ATTR
init_crc_table(void)
{
	uint32 c;
	uint32 i, j;

	crc_table = (uint32*)os_zalloc(256 * 4);
	if(crc_table == NULL){
		os_printf("malloc crc table failed\n");
		return -1;
	}
	for (i = 0; i < 256; i++) {
		c = (uint32)i;
		for (j = 0; j < 8; j++) {
			if (c & 1)
				c = 0xedb88320L ^ (c >> 1);
			else
				c = c >> 1;
		}
		crc_table[i] = c;
	}
	return 0;
}


static uint32 ICACHE_FLASH_ATTR
crc32(uint32 crc,unsigned char *buffer, uint32 size)
{
	uint32 i;
	for (i = 0; i < size; i++) {
		crc = crc_table[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);
	}
	return crc ;
}



static int ICACHE_FLASH_ATTR
calc_img_crc(uint32 sumlength,uint32 *img_crc)
{
	int fd;
	int ret;
	int i = 0;
	uint8 error = 0;
	unsigned char *buf = (char *)os_zalloc(BUFSIZE);
	if(buf == NULL){
		os_printf("malloc crc buf failed\n");
		os_free(crc_table);
		return -1;
    }

	uint32 crc = 0xffffffff;

	uint32 sec_block = sumlength / CRC_BLOCK_SIZE ;
	uint32 sec_last = sumlength % CRC_BLOCK_SIZE;
	for (i = 0; i < sec_block; i++) {
		if ( 0 != (error = spi_flash_read(start_sec * SPI_FLASH_SEC_SIZE + i * CRC_BLOCK_SIZE ,(uint32 *)buf, BUFSIZE))){
				os_free(crc_table);
				os_free(buf);
				os_printf("spi_flash_read error %d\n",error);
				return -1;
		}
		crc = crc32(crc, buf, BUFSIZE);
	}
	if(sec_last > 0 ) {
		if (0 != (error = spi_flash_read(start_sec * SPI_FLASH_SEC_SIZE + i * CRC_BLOCK_SIZE, (uint32 *)buf, sec_last))){
			os_free(crc_table);
			os_free(buf);
			os_printf("spi_flash_read error %d\n",error);
			return -1;
		}
		crc = crc32(crc, buf, sec_last);
	}
	*img_crc = crc;
	os_free(crc_table);
	os_free(buf);
	return 0;
}

int ICACHE_FLASH_ATTR
upgradetest_crc_check(uint16 fw_bin_sec ,unsigned int sumlength)
{
	int ret;
	unsigned int img_crc;
	unsigned int flash_crc = 0xFF;
	start_sec = fw_bin_sec;
	if ( 0 != init_crc_table()) {
		return false;
	}
	ret = calc_img_crc(sumlength - 4,&img_crc);
	if (ret < 0) {
		return false;
	}
	if(img_crc&(1<<31)){
		os_printf("img_crc = %u\n",img_crc);
		img_crc = ~img_crc+1;
	}
	os_printf("img_crc = %u\n",img_crc);
	spi_flash_read(start_sec * SPI_FLASH_SEC_SIZE + sumlength - 4,&flash_crc, 4);
    os_printf("flash_crc = %u\n",flash_crc);
	if(img_crc == flash_crc) {
	    return 1;
	} else {
		os_printf("upgrade crc check failed !\n");
		return -1;
	}
}
/*
 * CRC
 * */
int ICACHE_FLASH_ATTR
upgrade_bin_check(uint16 fw_bin_sec)
{
	uint8 bin;

	spi_flash_read(fw_bin_sec * SPI_FLASH_SEC_SIZE + 3,(uint32*)&bin, 1);
    os_printf("upgrade bin = %x\n",bin);
	if(bin != (system_upgrade_userbin_check()+1)) {
	    return 0;
	} else {
		os_printf("upgrade bin err !\n");
		return -1;
	}
}

LOCAL scaninfo *pscaninfo;
struct bss_info *bss;
struct bss_info *bss_temp;
struct bss_info *bss_head;
extern u16 scannum;
/******************************************************************************
 * FunctionName : device_get
 * Description  : set up the device information parmer as a JSON format
 * Parameters   : js_ctx -- A pointer to a JSON set up
 * Returns      : result
*******************************************************************************/
LOCAL int ICACHE_FLASH_ATTR
device_get(struct jsontree_context *js_ctx)
{
    const char *path = jsontree_path_name(js_ctx, js_ctx->depth - 1);

    if (os_strncmp(path, "manufacture", 11) == 0) {
        jsontree_write_string(js_ctx, "Nyear");
    } else if (os_strncmp(path, "product", 7) == 0) {
        jsontree_write_string(js_ctx, "Nyear_printer");
    } else if (os_strncmp(path, "ID", 7) == 0) {
        jsontree_write_string(js_ctx, sysCfg.device_id);
    }

    return 0;
}

LOCAL struct jsontree_callback device_callback =
    JSONTREE_CALLBACK(device_get, NULL);
/******************************************************************************
 * FunctionName : version_get
 * Description  : set up the device version paramer as a JSON format
 * Parameters   : js_ctx -- A pointer to a JSON set up
 * Returns      : result
*******************************************************************************/
LOCAL int ICACHE_FLASH_ATTR
version_get(struct jsontree_context *js_ctx)
{
    const char *path = jsontree_path_name(js_ctx, js_ctx->depth - 1);
    char string[32];

    if (os_strncmp(path, "hardware", 8) == 0) {
        os_sprintf(string, "0.1");
    } else if (os_strncmp(path, "sdk_version", 11) == 0) {
        os_sprintf(string, "%s", system_get_sdk_version());
    } else if (os_strncmp(path, "iot_version", 11) == 0) {
    	os_sprintf(string,"V%d.%d.%d",IOT_VERSION_MAJOR,IOT_VERSION_MINOR,IOT_VERSION_REVISION);
    }

    jsontree_write_string(js_ctx, string);

    return 0;
}

LOCAL struct jsontree_callback version_callback =
    JSONTREE_CALLBACK(version_get, NULL);

JSONTREE_OBJECT(device_tree,
                JSONTREE_PAIR("product", &device_callback),
                JSONTREE_PAIR("manufacturer", &device_callback),
				JSONTREE_PAIR("ID", &device_callback));
JSONTREE_OBJECT(version_tree,
                JSONTREE_PAIR("hardware", &version_callback),
                JSONTREE_PAIR("sdk_version", &version_callback),
                JSONTREE_PAIR("iot_version", &version_callback),
                );
JSONTREE_OBJECT(info_tree,
                JSONTREE_PAIR("Version", &version_tree),
                JSONTREE_PAIR("Device", &device_tree));

JSONTREE_OBJECT(INFOTree,
                JSONTREE_PAIR("info", &info_tree));
/******************************************************************************
 * FunctionName : userbin_get
 * Description  : get up the user bin paramer as a JSON format
 * Parameters   : js_ctx -- A pointer to a JSON set up
 * Returns      : result
*******************************************************************************/
LOCAL int ICACHE_FLASH_ATTR
userbin_get(struct jsontree_context *js_ctx)
{
    const char *path = jsontree_path_name(js_ctx, js_ctx->depth - 1);
    char string[32];

    if (os_strncmp(path, "status", 8) == 0) {
        os_sprintf(string, "200");
    } else if (os_strncmp(path, "user_bin", 8) == 0) {
    	if (system_upgrade_userbin_check() == 0x00) {
    		 os_sprintf(string, "user1.bin");
    	} else if (system_upgrade_userbin_check() == 0x01) {
    		 os_sprintf(string, "user2.bin");
    	} else{
    		return 0;
    	}
    }

    jsontree_write_string(js_ctx, string);

    return 0;
}

LOCAL struct jsontree_callback userbin_callback =
    JSONTREE_CALLBACK(userbin_get, NULL);

JSONTREE_OBJECT(userbin_tree,
                JSONTREE_PAIR("status", &userbin_callback),
                JSONTREE_PAIR("user_bin", &userbin_callback));
JSONTREE_OBJECT(userinfo_tree,JSONTREE_PAIR("user_info",&userbin_tree));
/******************************************************************************
 *
 ******************************************************************************/
LOCAL int ICACHE_FLASH_ATTR
wifi_rssi_get(struct jsontree_context *js_ctx)
{
    const char *path = jsontree_path_name(js_ctx, js_ctx->depth - 1);
    char string[32];

    if (os_strncmp(path, "status", 8) == 0) {
        os_sprintf(string, "200");
    } else if (os_strncmp(path, "rssi", 8) == 0) {
    	os_sprintf(string, "%d", wifi_station_get_rssi());
    }

    jsontree_write_string(js_ctx, string);

    return 0;
}

LOCAL struct jsontree_callback rssi_callback =
    JSONTREE_CALLBACK(wifi_rssi_get, NULL);

JSONTREE_OBJECT(rssi_tree,
                JSONTREE_PAIR("status", &rssi_callback),
                JSONTREE_PAIR("rssi", &rssi_callback));
JSONTREE_OBJECT(wifi_rssi_tree,JSONTREE_PAIR("wifi_rssi",&rssi_tree));
/******************************************************************************
 * FunctionName : scan_get
 * Description  : set up the scan data as a JSON format
 * Parameters   : js_ctx -- A pointer to a JSON set up
 * Returns      : result
*******************************************************************************/

LOCAL int ICACHE_FLASH_ATTR
scan_get(struct jsontree_context *js_ctx)
{
    const char *path = jsontree_path_name(js_ctx, js_ctx->depth - 1);
    //    STAILQ_HEAD(, bss_info) *pbss = scanarg;
//    LOCAL struct bss_info *bss;

    if (os_strncmp(path, "TotalPage", 9) == 0) {
        jsontree_write_int(js_ctx, pscaninfo->totalpage);
    } else if (os_strncmp(path, "PageNum", 7) == 0) {
        jsontree_write_int(js_ctx, pscaninfo->pagenum);
    } else if (os_strncmp(path, "bssid", 5) == 0) {
    	if( bss == NULL )
    		bss = bss_head;
        u8 buffer[32];
        //if (bss != NULL){
        os_memset(buffer, 0, sizeof(buffer));
        os_sprintf(buffer, MACSTR, MAC2STR(bss->bssid));
        jsontree_write_string(js_ctx, buffer);
        //}
    } else if (os_strncmp(path, "ssid", 4) == 0) {
        //if (bss != NULL)
        jsontree_write_string(js_ctx, bss->ssid);
    } else if (os_strncmp(path, "rssi", 4) == 0) {
        //if (bss != NULL)
        jsontree_write_int(js_ctx, -(bss->rssi));
    } else if (os_strncmp(path, "channel", 7) == 0) {
        //if (bss != NULL)
        jsontree_write_int(js_ctx, bss->channel);
    } else if (os_strncmp(path, "authmode", 8) == 0) {
        //if (bss != NULL){
        switch (bss->authmode) {
            case AUTH_OPEN:
                jsontree_write_string(js_ctx, "OPEN");
                break;

            case AUTH_WEP:
                jsontree_write_string(js_ctx, "WEP");
                break;

            case AUTH_WPA_PSK:
                jsontree_write_string(js_ctx, "WPAPSK");
                break;

            case AUTH_WPA2_PSK:
                jsontree_write_string(js_ctx, "WPA2PSK");
                break;

            case AUTH_WPA_WPA2_PSK:
                jsontree_write_string(js_ctx, "WPAPSK/WPA2PSK");
                break;

            default :
                jsontree_write_int(js_ctx, bss->authmode);
                break;
        }

        bss = STAILQ_NEXT(bss, next);
//        os_free(bss);
        //}
    }

    return 0;
}

LOCAL struct jsontree_callback scan_callback =
    JSONTREE_CALLBACK(scan_get, NULL);

JSONTREE_OBJECT(scaninfo_tree,
                JSONTREE_PAIR("bssid", &scan_callback),
                JSONTREE_PAIR("ssid", &scan_callback),
                JSONTREE_PAIR("rssi", &scan_callback),
                JSONTREE_PAIR("channel", &scan_callback),
                JSONTREE_PAIR("authmode", &scan_callback));
JSONTREE_ARRAY(scanrslt_tree,
               JSONTREE_PAIR_ARRAY(&scaninfo_tree),
               JSONTREE_PAIR_ARRAY(&scaninfo_tree),
               JSONTREE_PAIR_ARRAY(&scaninfo_tree),
               JSONTREE_PAIR_ARRAY(&scaninfo_tree),
               JSONTREE_PAIR_ARRAY(&scaninfo_tree),
               JSONTREE_PAIR_ARRAY(&scaninfo_tree),
               JSONTREE_PAIR_ARRAY(&scaninfo_tree),
               JSONTREE_PAIR_ARRAY(&scaninfo_tree));

JSONTREE_OBJECT(scantree,
                JSONTREE_PAIR("TotalPage", &scan_callback),
                JSONTREE_PAIR("PageNum", &scan_callback),
                JSONTREE_PAIR("ScanResult", &scanrslt_tree));
JSONTREE_OBJECT(scanres_tree,
                JSONTREE_PAIR("Response", &scantree));
JSONTREE_OBJECT(scan_tree,
                JSONTREE_PAIR("scan", &scanres_tree));
/******************************************************************************
 *
 ******************************************************************************/
bool ICACHE_FLASH_ATTR wifi_set(void *arg, char *pdata) {
	bool ret = 0;
	cJSON *root = cJSON_Parse(pdata);
	cJSON * Result = cJSON_CreateObject();
	if (!root) {
//		os_printf("Error before: [%s]\n", cJSON_GetErrorPtr());
		cJSON_AddStringToObject(Result, "JSON Error before:", cJSON_GetErrorPtr());
		char *succeedData = cJSON_Print(Result);
		espconn_send((struct espconn *) arg, succeedData, strlen(succeedData));

	} else {
		cJSON *ssid_json,*psw_json;
		cJSON *state_json = cJSON_GetObjectItem(root, "state");

		if(state_json!=NULL){
			if(state_json->type==cJSON_Number)
			switch (state_json->valueint)
			{case 1:
/*				cJSON_AddNumberToObject(Result, "status", 0);
				if (wifi_station_get_connect_status() == STATION_GOT_IP) {
					cJSON_AddStringToObject(Result, "msg", "STATION_CONNECT_SUCCEED");
					char *succeedData = cJSON_Print(Result);
					espconn_send((struct espconn *) arg, succeedData, strlen(succeedData));
				}
				else
				{
					cJSON_AddStringToObject(Result, "msg", "STATION_CONNECT_FAIL");
					char *succeedData = cJSON_Print(Result);
					espconn_send((struct espconn *) arg, succeedData, strlen(succeedData));
				}*/
				break;
			case 0:
			    if(Server_Mode!=MQTT_CLIENT){
			        Server_Mode=MQTT_CLIENT;
			    	spi_flash_erase_sector(0x79 + 2);
			    	spi_flash_write((0x79 + 2) * 4096,(uint32 *)&Server_Mode, sizeof(Server_Mode));
			    }
				break;
			}
			ssid_json = cJSON_GetObjectItem(root, "ssid");
			psw_json = cJSON_GetObjectItem(root, "psw");
			if (ssid_json && psw_json) {
				if (ssid_json->type==cJSON_String && psw_json->type==cJSON_String)
					WIFI_Connect(ssid_json->valuestring, psw_json->valuestring);
			   if(Server_Mode == AP_MODE){
					Server_Mode=TCP_SERVER;
					spi_flash_erase_sector(0x79 + 2);
					spi_flash_write((0x79 + 2) * 4096,(uint32 *)&Server_Mode, sizeof(Server_Mode));
				}
			}
		}
		ret = 1;
	}
	cJSON_Delete(Result);
	cJSON_Delete(root);
	return ret;
}
/******************************************************************************
 * FunctionName : data_send
 * Description  : processing the data as http format and send to the client or server
 * Parameters   : arg -- argument to set for client or server
 *                responseOK -- true or false
 *                psend -- The send data
 * Returns      :
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
data_send(void *arg, bool responseOK, char *psend)
{
    uint16 length = 0;
    uint32 ts = 0;
    char *pbuf = NULL;
    char httphead[256];
    struct espconn *ptrespconn = arg;
    os_memset(httphead, 0, 256);

    if (responseOK) {
        os_sprintf(httphead,
                   "HTTP/1.0 200 OK\r\nContent-Length: %d\r\nServer: lwIP/1.4.0\r\naccess-control-allow-origin:*\r\n",
                   psend ? os_strlen(psend) : 0);

        if (psend) {
            ts = sntp_get_current_timestamp();
        	if(os_strlen(psend)<2000)
        		os_sprintf(httphead + os_strlen(httphead),
                       "Content-type: application/json\r\nExpires: %s GMT\r\nPragma: no-cache\r\n\r\n",sntp_get_real_time(ts));
        	else
        		os_sprintf(httphead + os_strlen(httphead),
        		       "Content-type: text/html\r\nExpires: %s GMT\r\nPragma: no-cache\r\n\r\n",sntp_get_real_time(ts));
            length = os_strlen(httphead) + os_strlen(psend);
            pbuf = (char *)os_zalloc(length + 1);
            os_memcpy(pbuf, httphead, os_strlen(httphead));
            os_memcpy(pbuf + os_strlen(httphead), psend, os_strlen(psend));
        } else {
            os_sprintf(httphead + os_strlen(httphead), "\n");
            length = os_strlen(httphead);
        }
    } else {
        os_sprintf(httphead, "HTTP/1.0 400 BadRequest\r\n\
Content-Length: 0\r\naccess-control-allow-origin:*\r\nServer: lwIP/1.4.0\r\n\n");
        length = os_strlen(httphead);
    }

    if (psend) {
#ifdef SERVER_SSL_ENABLE
        espconn_secure_sent(ptrespconn, pbuf, length);
#else
        espconn_sent(ptrespconn, pbuf, length);
#endif
    } else {
#ifdef SERVER_SSL_ENABLE
        espconn_secure_sent(ptrespconn, httphead, length);
#else
        espconn_sent(ptrespconn, httphead, length);
#endif
    }

    if (pbuf) {
        os_free(pbuf);
        pbuf = NULL;
    }
}

/******************************************************************************
 * FunctionName : json_send
 * Description  : processing the data as json format and send to the client or server
 * Parameters   : arg -- argument to set for client or server
 *                ParmType -- json format type
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
json_send(void *arg, ParmType ParmType)
{
    char *pbuf = NULL;
    pbuf = (char *)os_zalloc(jsonSize);
    struct espconn *ptrespconn = arg;

    char *index = NULL;
    SpiFlashOpResult ret = 0;
	uint16 FLASH_READ_SIZE;
	uint8 lens[5];

    switch (ParmType) {
        case INFOMATION:
            json_ws_send((struct jsontree_value *)&INFOTree, "info", pbuf);
            break;

        case RSSI:
            json_ws_send((struct jsontree_value *)&wifi_rssi_tree, "wifi_rssi", pbuf);
            break;
/*
		case WIFI:
            json_ws_send((struct jsontree_value *)&wifi_rssi_tree, "rssi", pbuf);
            break;
        case CONNECT_STATUS:
            json_ws_send((struct jsontree_value *)&con_status_tree, "info", pbuf);
            break;
*/
#if 1
        case INDEX:
                	spi_flash_read(0x110*SPI_FLASH_SEC_SIZE, (uint32 *)lens, 4);
                	lens[4] = 0;
                	FLASH_READ_SIZE = atoi(lens);

                	index = (char *)os_zalloc(FLASH_READ_SIZE+1);
                	if(index == NULL){
                		os_printf("os_zalloc error!\r\n");
                		break;
                	}

                	// Flash read/write has to be aligned to the 4-bytes boundary
                	ret = spi_flash_read(0x110*SPI_FLASH_SEC_SIZE+6, (uint32 *)index, FLASH_READ_SIZE);  // start address:0x10000 + 0xC0000
                	if(ret != SPI_FLASH_RESULT_OK){
                		os_printf("spi_flash_read err:%d\r\n", ret);
                		os_free(index);
                		index = NULL;
                		break;
                	}

                	index[FLASH_READ_SIZE] = 0;   // put 0 to the end
                	data_send(ptrespconn, true, index);

                	os_free(index);
                	index = NULL;
        	break;
#endif
        case USER_BIN:
        	json_ws_send((struct jsontree_value *)&userinfo_tree, "user_info", pbuf);
        	break;
        case SCAN: {
            u8 i = 0;
            u8 scancount = 0;
            struct bss_info *bss = NULL;
//            bss = STAILQ_FIRST(pscaninfo->pbss);
            bss = bss_head;
            if (bss == NULL) {
                os_free(pscaninfo);
                pscaninfo = NULL;
                os_sprintf(pbuf, "{\n\"successful\": false,\n\"data\": null\n}");
            } else {
                do {
                    if (pscaninfo->page_sn == pscaninfo->pagenum) {
                        pscaninfo->page_sn = 0;
                        os_sprintf(pbuf, "{\n\"successful\": false,\n\"meessage\": \"repeated page\"\n}");
                        break;
                    }

                    scancount = scannum - (pscaninfo->pagenum - 1) * 8;

                    if (scancount >= 8) {
                        pscaninfo->data_cnt += 8;
                        pscaninfo->page_sn = pscaninfo->pagenum;

                        if (pscaninfo->data_cnt > scannum) {
                            pscaninfo->data_cnt -= 8;
                            os_sprintf(pbuf, "{\n\"successful\": false,\n\"meessage\": \"error page\"\n}");
                            break;
                        }

                        json_ws_send((struct jsontree_value *)&scan_tree, "scan", pbuf);
                    } else {
                        pscaninfo->data_cnt += scancount;
                        pscaninfo->page_sn = pscaninfo->pagenum;

                        if (pscaninfo->data_cnt > scannum) {
                            pscaninfo->data_cnt -= scancount;
                            os_sprintf(pbuf, "{\n\"successful\": false,\n\"meessage\": \"error page\"\n}");
                            break;
                        }

                        char *ptrscanbuf = (char *)os_zalloc(jsonSize);
                        char *pscanbuf = ptrscanbuf;
                        os_sprintf(pscanbuf, ",\n\"ScanResult\": [\n");
                        pscanbuf += os_strlen(pscanbuf);

                        for (i = 0; i < scancount; i ++) {
                            JSONTREE_OBJECT(page_tree,
                                            JSONTREE_PAIR("page", &scaninfo_tree));
                            json_ws_send((struct jsontree_value *)&page_tree, "page", pscanbuf);
                            os_sprintf(pscanbuf + os_strlen(pscanbuf), ",\n");
                            pscanbuf += os_strlen(pscanbuf);
                        }

                        os_sprintf(pscanbuf - 2, "]\n");
                        JSONTREE_OBJECT(scantree,
                                        JSONTREE_PAIR("TotalPage", &scan_callback),
                                        JSONTREE_PAIR("PageNum", &scan_callback));
                        JSONTREE_OBJECT(scanres_tree,
                                        JSONTREE_PAIR("Response", &scantree));
                        JSONTREE_OBJECT(scan_tree,
                                        JSONTREE_PAIR("scan", &scanres_tree));
                        json_ws_send((struct jsontree_value *)&scan_tree, "scan", pbuf);
                        os_memcpy(pbuf + os_strlen(pbuf) - 4, ptrscanbuf, os_strlen(ptrscanbuf));
                        os_sprintf(pbuf + os_strlen(pbuf), "}\n}");
                        os_free(ptrscanbuf);
                    }
                } while (0);
            }

            break;
        }

        default :
            break;
    }

    data_send(ptrespconn, true, pbuf);
    os_free(pbuf);
    pbuf = NULL;
}

/******************************************************************************
 * FunctionName : json_scan_cb
 * Description  : processing the scan result
 * Parameters   : arg -- Additional argument to pass to the callback function
 *                status -- scan status
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR json_scan_cb(void *arg, STATUS status)
{
    pscaninfo->pbss = arg;

    if (scannum % 8 == 0) {
        pscaninfo->totalpage = scannum / 8;
    } else {
        pscaninfo->totalpage = scannum / 8 + 1;
    }

    JSONTREE_OBJECT(totaltree,
                    JSONTREE_PAIR("TotalPage", &scan_callback));
    JSONTREE_OBJECT(totalres_tree,
                    JSONTREE_PAIR("Response", &totaltree));
    JSONTREE_OBJECT(total_tree,
                    JSONTREE_PAIR("total", &totalres_tree));

    bss_temp = bss_head;
    while(bss_temp !=NULL) {
    	bss_head = bss_temp->next.stqe_next;
    	os_free(bss_temp);
    	bss_temp = bss_head;
    }
    bss_head = NULL;
    bss_temp = NULL;
    bss = STAILQ_FIRST(pscaninfo->pbss);
    while(bss != NULL) {
    	if(bss_temp == NULL){
    		bss_temp = (struct bss_info *)os_zalloc(sizeof(struct bss_info));
    		bss_head = bss_temp;
    	} else {
    		bss_temp->next.stqe_next = (struct bss_info *)os_zalloc(sizeof(struct bss_info));
    		bss_temp = bss_temp->next.stqe_next;
    	}
    	if(bss_temp == NULL) {
    		os_printf("malloc scan info failed\n");
    		break;
    	} else{
    		os_memcpy(bss_temp->bssid,bss->bssid,sizeof(bss->bssid));
    		os_memcpy(bss_temp->ssid,bss->ssid,sizeof(bss->ssid));
    		bss_temp->authmode = bss->authmode;
    		bss_temp->rssi = bss->rssi;
    		bss_temp->channel = bss->channel;
    	}
    	bss = STAILQ_NEXT(bss,next);
    }
    char *pbuf = NULL;
    pbuf = (char *)os_zalloc(jsonSize);
    json_ws_send((struct jsontree_value *)&total_tree, "total", pbuf);
    data_send(pscaninfo->pespconn, true, pbuf);
    os_free(pbuf);
}
/******************************************************************************
 * FunctionName : response_send
 * Description  : processing the send result
 * Parameters   : arg -- argument to set for client or server
 *                responseOK --  true or false
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
response_send(void *arg, bool responseOK)
{
    struct espconn *ptrespconn = arg;

    data_send(ptrespconn, responseOK, NULL);
}

/******************************************************************************
 * FunctionName : parse_url
 * Description  : parse the received data from the server
 * Parameters   : precv -- the received data
 *                purl_frame -- the result of parsing the url
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
parse_url(char *precv, URL_Frame *purl_frame)
{
    char *str = NULL;
    uint8 length = 0;
    char *pbuffer = NULL;
    char *pbufer = NULL;

    if (purl_frame == NULL || precv == NULL) {
        return;
    }

    pbuffer = (char *)os_strstr(precv, "Host:");

    if (pbuffer != NULL) {
        length = pbuffer - precv;
        pbufer = (char *)os_zalloc(length + 1);
        pbuffer = pbufer;
        os_memcpy(pbuffer, precv, length);
        os_memset(purl_frame->pSelect, 0, URLSize);
        os_memset(purl_frame->pCommand, 0, URLSize);
        os_memset(purl_frame->pFilename, 0, URLSize);

        if (os_strncmp(pbuffer, "GET ", 4) == 0) {
            purl_frame->Type = GET;
            pbuffer += 4;
        } else if (os_strncmp(pbuffer, "POST ", 5) == 0) {
            purl_frame->Type = POST;
            pbuffer += 5;
        }

        pbuffer ++;
        str = (char *)os_strstr(pbuffer, "?");

        if (str != NULL) {
            length = str - pbuffer;
            os_memcpy(purl_frame->pSelect, pbuffer, length);
            str ++;
            pbuffer = (char *)os_strstr(str, "=");

            if (pbuffer != NULL) {
                length = pbuffer - str;
                os_memcpy(purl_frame->pCommand, str, length);
                pbuffer ++;
                str = (char *)os_strstr(pbuffer, "&");

                if (str != NULL) {
                    length = str - pbuffer;
                    os_memcpy(purl_frame->pFilename, pbuffer, length);
                } else {
                    str = (char *)os_strstr(pbuffer, " HTTP");

                    if (str != NULL) {
                        length = str - pbuffer;
                        os_memcpy(purl_frame->pFilename, pbuffer, length);
                    }
                }
            }
        }

        os_free(pbufer);
    } else {
        return;
    }
}

void ICACHE_FLASH_ATTR upgrade_finish(void){
	uart0_sendStr("close Uart\r\n");
	system_upgrade_reboot();
}

void ICACHE_FLASH_ATTR
upgrade_check_func(void *arg)
{
	struct espconn *ptrespconn = arg;
	os_timer_disarm(&upgrade_check_timer);
	if(system_upgrade_flag_check() == UPGRADE_FLAG_START) {
		response_send(ptrespconn, false);
        system_upgrade_deinit();
        system_upgrade_flag_set(UPGRADE_FLAG_IDLE);
        upgrade_lock = 0;
		os_printf("local upgrade failed\n");
		uart0_sendStr("Upgrade failed.\r\n\r\n\r\n");
	} else if( system_upgrade_flag_check() == UPGRADE_FLAG_FINISH ) {
		response_send(ptrespconn, true);
		os_printf("local upgrade success\n");
		uart0_sendStr("Upgrade success.\r\n\r\n\r\n");
//		data_send(ptrespconn, true, "upgrade success");
		upgrade_lock = 0;
	} else {

	}
}
/******************************************************************************
 * FunctionName : upgrade_deinit
 * Description  : disconnect the connection with the host
 * Parameters   : bin -- server number
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR
LOCAL local_upgrade_deinit(void)
{
    if (system_upgrade_flag_check() != UPGRADE_FLAG_START) {
    	os_printf("system upgrade deinit\n");
        system_upgrade_deinit();
    }
}

/******************************************************************************
 * FunctionName : upgrade_download
 * Description  : Processing the upgrade data from the host
 * Parameters   : bin -- server number
 *                pusrdata -- The upgrade data (or NULL when the connection has been closed!)
 *                length -- The length of upgrade data
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
local_upgrade_download(void * arg,char *pusrdata, unsigned short length)
{
    char *ptr = NULL;
    char *ptmp2 = NULL;
    char lengthbuffer[32];
    static uint32 totallength = 0;
    static uint32 sumlength = 0;
    static uint32 erase_length = 0;
    static bool upgrade_write = 0;
//    char A_buf[2] = {0xE9 ,0x03}; char	B_buf[2] = {0xEA,0x04};
    struct espconn *pespconn = arg;

    if (totallength == 0 && (ptr = (char *)os_strstr(pusrdata, "\r\n\r\n")) != NULL &&
            (ptr = (char *)os_strstr(pusrdata, "Content-Length")) != NULL) {
    	ptr = (char *)os_strstr(pusrdata, "Content-Length: ");
		if (ptr != NULL) {
			ptr += 16;
			ptmp2 = (char *)os_strstr(ptr, "\r\n");

			if (ptmp2 != NULL) {
				os_memset(lengthbuffer, 0, sizeof(lengthbuffer));
				os_memcpy(lengthbuffer, ptr, ptmp2 - ptr);
				sumlength = atoi(lengthbuffer);
				if (sumlength == 0) {
					os_timer_disarm(&upgrade_check_timer);
					os_timer_setfn(&upgrade_check_timer, (os_timer_func_t *)upgrade_check_func, pespconn);
					os_timer_arm(&upgrade_check_timer, 10, 0);
					return;
				}
			} else {
				os_printf("sumlength failed\n");
				return;
			}
		} else {
			os_printf("Content-Length: failed\n");
			return;
		}

		upgrade_write = 1;
        ptr = (char *)os_strstr(pusrdata, "\r\n\r\n");
        length -= ptr - pusrdata;
        length -= 4;
        totallength += length;
		os_printf("upgrade file download start.\n");

		erase_length = sumlength;

		if(totallength>0){
			if (sumlength != 0) {
				if (sumlength >= LIMIT_ERASE_SIZE){
					system_upgrade_erase_flash(0xFFFF);
					erase_length -= LIMIT_ERASE_SIZE;
					os_printf("erase 0x10000\r\n");
				} else {
					system_upgrade_erase_flash(sumlength);
					erase_length = 0;
					os_printf("erase 0x%x\r\n",sumlength);
				}
			}
			system_upgrade(ptr + 4, length);
		}
    } else {
    	if(sumlength != 0){
    		totallength += length;
            if (erase_length >= LIMIT_ERASE_SIZE){
    			system_upgrade_erase_flash(0xFFFF);
    			erase_length -= LIMIT_ERASE_SIZE;
    			os_printf("erase 0x10000\r\n");
    		} else {
    			system_upgrade_erase_flash(erase_length);
    			if(erase_length > 0)
    				os_printf("erase 0x%x\r\n",erase_length);
    			erase_length = 0;
    		}
            system_upgrade(pusrdata, length);
            os_printf("download : %d, %d\r\n",totallength,totallength*100/sumlength);
    	}
    }

    if (totallength >= sumlength && sumlength != 0) {
        os_printf("upgrade file download finished.\n");

        uint16 user_bin2_start;
    	uint8 spi_size_map = system_get_flash_size_map();

    	if (spi_size_map == FLASH_SIZE_8M_MAP_512_512 ||
    			spi_size_map ==FLASH_SIZE_16M_MAP_512_512 ||
    			spi_size_map ==FLASH_SIZE_32M_MAP_512_512){
    			user_bin2_start = 129;//123 sec鍙敤
    	} else if(spi_size_map == FLASH_SIZE_16M_MAP_1024_1024 ||
    			spi_size_map == FLASH_SIZE_32M_MAP_1024_1024){
    			user_bin2_start = 257;//251 sec鍙敤
    	} else {
    			user_bin2_start = 65;//59 sec鍙敤
    	}
    	uint16 addr = (system_upgrade_userbin_check() == USER_BIN1) ? user_bin2_start : 1;

		if((upgradetest_crc_check(addr,sumlength) == 1)&& (upgrade_bin_check(addr) == 0))//
		{
			system_upgrade_flag_set(UPGRADE_FLAG_FINISH);
		}
		totallength = 0;
		sumlength = 0;
        upgrade_check_func(pespconn);
		os_timer_disarm(&app_upgrade_10s);
		os_timer_setfn(&app_upgrade_10s, (os_timer_func_t *)local_upgrade_deinit, NULL);
		os_timer_arm(&app_upgrade_10s, 10, 0);
    }
}

LOCAL char *precvbuffer;
static uint32 dat_sumlength = 0;
LOCAL bool ICACHE_FLASH_ATTR
save_data(char *precv, uint16 length)
{
    bool flag = false;
    char length_buf[10] = {0};
    char *ptemp = NULL;
    char *pdata = NULL;
    uint16 headlength = 0;
    static uint32 totallength = 0;

    ptemp = (char *)os_strstr(precv, "\r\n\r\n");

    if (ptemp != NULL) {
        length -= ptemp - precv;
        length -= 4;
        totallength += length;
        headlength = ptemp - precv + 4;
        pdata = (char *)os_strstr(precv, "Content-Length: ");

        if (pdata != NULL) {
            pdata += 16;
            precvbuffer = (char *)os_strstr(pdata, "\r\n");

            if (precvbuffer != NULL) {
                os_memcpy(length_buf, pdata, precvbuffer - pdata);
                dat_sumlength = atoi(length_buf);
            }
        } else {
        	if (totallength != 0x00){
        		totallength = 0;
        		dat_sumlength = 0;
        		return false;
        	}
        }
        if ((dat_sumlength + headlength) >= 1024) {
        	precvbuffer = (char *)os_zalloc(headlength + 1);
            os_memcpy(precvbuffer, precv, headlength + 1);
        } else {
        	precvbuffer = (char *)os_zalloc(dat_sumlength + headlength + 1);
        	os_memcpy(precvbuffer, precv, os_strlen(precv));
        }
    } else {
        if (precvbuffer != NULL) {
            totallength += length;
            os_memcpy(precvbuffer + os_strlen(precvbuffer), precv, length);
        } else {
            totallength = 0;
            dat_sumlength = 0;
            return false;
        }
    }

    if (totallength == dat_sumlength) {
        totallength = 0;
        dat_sumlength = 0;
        return true;
    } else {
        return false;
    }
}

LOCAL bool ICACHE_FLASH_ATTR
check_data(char *precv, uint16 length)
{
//    bool flag = false;
    char length_buf[10] = {0};
    char *ptemp = NULL;
    char *pdata = NULL;
    char *tmp_precvbuffer;
    uint16 tmp_length = length;
    uint32 tmp_totallength = 0;

    if (((os_strncmp(precv, "GET ", 4) == 0)
    		||(os_strncmp(precv, "POST ", 5) == 0))
    		&&os_strstr(precv, " HTTP")){
    		ptemp = (char *)os_strstr(precv, "\r\n\r\n");

			if (ptemp != NULL) {
				tmp_length -= ptemp - precv;
				tmp_length -= 4;
				tmp_totallength += tmp_length;

				pdata = (char *)os_strstr(precv, "Content-Length: ");

				if (pdata != NULL){
					pdata += 16;
					tmp_precvbuffer = (char *)os_strstr(pdata, "\r\n");

					if (tmp_precvbuffer != NULL){
						os_memcpy(length_buf, pdata, tmp_precvbuffer - pdata);
						dat_sumlength = atoi(length_buf);
						os_printf("A_dat:%u,tot:%u,lenght:%u\n",dat_sumlength,tmp_totallength,tmp_length);
						if(dat_sumlength != tmp_totallength){
							return false;
//							goto check_exit;
						}
					}
				}
			}
			return true;
    }
//    check_exit:
    return false;
}
/*************************************************************************
 *
 ***********************************************************************/
void ICACHE_FLASH_ATTR smartcfg_cb(void){
	os_timer_disarm(&app_upgrade_10s);
	wifi_station_disconnect();
	smartconfig_stop();
	smart_config();
}
void ICACHE_FLASH_ATTR apmode_cb(void){
	os_timer_disarm(&app_upgrade_10s);
	wifi_station_disconnect();
	WIFI_Init();
	Inter213_InitTCP(8266);
}
void ICACHE_FLASH_ATTR reset_cb(void){
	os_timer_disarm(&app_upgrade_10s);
    uart0_sendStr("close Uart\r\n");
    system_restore();
    os_delay_us(60000);
    system_restart();
}
void ICACHE_FLASH_ATTR wifimode_cb(uint8* arg){

    uart0_sendStr("close Uart\r\n");
    if(Server_Mode!=TCP_SERVER){
        Server_Mode=TCP_SERVER;
    	spi_flash_erase_sector(0x79 + 2);
    	spi_flash_write((0x79 + 2) * 4096,(uint32 *)&Server_Mode, sizeof(Server_Mode));
    }
	os_delay_us(60000);
	os_delay_us(60000);
	system_restart();
}
void ICACHE_FLASH_ATTR mqttmode_cb(uint8* arg){

    uart0_sendStr("close Uart\r\n");
    if(Server_Mode!=MQTT_CLIENT){
        Server_Mode=MQTT_CLIENT;
    	spi_flash_erase_sector(0x79 + 2);
    	spi_flash_write((0x79 + 2) * 4096,(uint32 *)&Server_Mode, sizeof(Server_Mode));
    }
	os_delay_us(60000);
	os_delay_us(60000);
	system_restart();
}
extern bool stopsend;
I16 ICACHE_FLASH_ATTR Queue_outRb(RINGBUF* rb, U16* len, U16 maxBufLen)
{
	U8 c;
	U16 dataLen = 0;

	while(RINGBUF_Get(rb, &c) == 0){
		dataLen++;
		uart_tx_one_char(UART0, c);
		// uart_tx_one_char(UART1, c);
		if((rb->fill_cnt==0)||(dataLen==maxBufLen)||(stopsend == true))
		{
			*len = dataLen;
//			uint32 time = system_get_time();
//			os_printf("---------endtime:%3d.%3d \r\n",time/1000000,(time/1000)%1000);
			return 0;
		}
	}
	return -1;
}

I16 ICACHE_FLASH_ATTR Queue_AddRb(RINGBUF *rb, const U8 *packet, I16 len)
{
    U16 i = 1;
    while (len--) {
		if(RINGBUF_Put(rb, *packet++) == -1) return -1;
		i++;
    }

    return i;
}

static QUEUE msgQueue;
uint8 holdnum = 0;
bool iscommand = false;
extern recon_info RemotBuf[Client_Num];

void ICACHE_FLASH_ATTR Queueinit(uint32 buf_size){
	uint32 heap_size = system_get_free_heap_size();
	    if(heap_size <=buf_size){
	    	os_printf("no buf for uart\n\r");
	    }else{
	    	os_printf("test heap size: %d\n\r",heap_size);
	    	QUEUE_Init(&msgQueue, buf_size);
	    	os_printf("test heap size: %d\n\r",system_get_free_heap_size());
	    }
}

void outputdata(void *arg){
	uint16_t dataLen;
	struct espconn *ptrespconn = (struct espconn *)arg;
	//闈炵┖鍒欏彂閫�
	uint32 time = system_get_time();
	if(QUEUE_IsEmpty(&msgQueue)==0){//upgrade_lock == 0 &&
		Queue_outRb(&msgQueue.rb, &dataLen, 900);
    	os_printf("---------output:%d time:%3d.%3d queue:%d\r\n",dataLen,time/1000000,(time/1000)%1000,msgQueue.rb.fill_cnt);
    	if(msgQueue.rb.fill_cnt <= 2000 && holdnum){
#if Client_Num == 1
    		//espconn_recv_unhold(ptrespconn);
    		//holdnum = false;
#else
    		uint8 i;
    		for(i=0;i<Client_Num;i++)
    		{
        		if((holdnum&(0x01<<i))>>i){
        			holdnum^=(0x01<<i);
        			ptrespconn->proto.tcp->remote_port = RemotBuf[i].remote_port;
    				os_memcpy(ptrespconn->proto.tcp->remote_ip,RemotBuf[i].remote_ip,4);
    				//ptrespconn->proto.tcp->local_port = RemotBuf[i].local_port;
        			espconn_recv_unhold(ptrespconn);
        		}
    		}
#endif
    		os_printf("Receive enable\n\r");
    	}
	}
}

uint16_t ICACHE_FLASH_ATTR getqueuelens(void){
	return msgQueue.rb.fill_cnt;
}
/******************************************************************************
 * FunctionName : webserver_recv
 * Description  : Processing the received data from the server
 * Parameters   : arg -- Additional argument to pass to the callback function
 *                pusrdata -- The received data (or NULL when the connection has been closed!)
 *                length -- The length of received data
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR
webserver_recv(void *arg, char *pusrdata, unsigned short length)
{
    URL_Frame *pURL_Frame = NULL;
    char *pParseBuffer = NULL;
    bool parse_flag = false;
    struct espconn *ptrespconn = (struct espconn *)arg;
    static uint32 lasttime=0;
    uint8 i;
#if Client_Num == 1
//    if(holdnum == false){// && ptrespconn->proto.tcp->local_port == 8266
//		espconn_recv_hold(ptrespconn); //闃诲
//		holdnum = true;
//    }
#else
    for(i=0;i<Client_Num;i++){
		if(RemotBuf[i].state == 3
			&& os_strncmp(RemotBuf[i].remote_ip,ptrespconn->proto.tcp->remote_ip,4) == 0
			&& RemotBuf[i].remote_port == ptrespconn->proto.tcp->remote_port){
			if((holdnum&(0x01<<i))>>i == false){
				holdnum |= (0x01<<i);
				espconn_recv_hold(ptrespconn);
			}
			break;
		}
    }
//    os_printf("%8x-----------\r\n",holdnum);
#endif

    if(upgrade_lock == 0){
        if(check_data(pusrdata, length) == false)
        {
#if Queue_en
        	if (Queue_AddRb(&msgQueue.rb, pusrdata, length) == -1) {
                os_printf("Queue full\r\n");
            }
        	uint32 time = system_get_time();
/*for(x=0;x<length;x++){
	uart_tx_one_char(UART1, pusrdata[x]);
}*/
        	os_printf("time:%3d.%3d,equation:%3d,len:%u Queue:%d\r\n",time/1000000,(time/1000)%1000,(time-lasttime)/1000,length,msgQueue.rb.fill_cnt);
        	lasttime=time;

#else
            uart0_tx_buffer(pusrdata,length);
            espconn_recv_unhold(ptrespconn);
#endif
            goto _temp_exit;
        }
        os_printf("Receive len:%u\n",length);
        iscommand = true;
    	parse_flag = save_data(pusrdata, length);
        if (parse_flag == false) {
        	response_send(ptrespconn, false);
        }

        //os_printf("%s\r\n",precvbuffer);
        pURL_Frame = (URL_Frame *)os_zalloc(sizeof(URL_Frame));
        parse_url(precvbuffer, pURL_Frame);

        switch (pURL_Frame->Type) {
            case GET:
                os_printf("We have a GET request.\n");

				if (os_strcmp(pURL_Frame->pSelect, "client") == 0 &&
						os_strcmp(pURL_Frame->pCommand, "command") == 0) {
					if (os_strcmp(pURL_Frame->pFilename, "info") == 0) {
						json_send(ptrespconn, INFOMATION);
					}
					if (os_strcmp(pURL_Frame->pFilename, "rssi") == 0) {
						json_send(ptrespconn, RSSI);
					}
					if (os_strcmp(pURL_Frame->pFilename, "scan") == 0) {
						char *strstr = NULL;
						strstr = (char *)os_strstr(pusrdata, "&");

						if (strstr == NULL) {
							if (pscaninfo == NULL) {
								pscaninfo = (scaninfo *)os_zalloc(sizeof(scaninfo));
							}

							pscaninfo->pespconn = ptrespconn;
							pscaninfo->pagenum = 0;
							pscaninfo->page_sn = 0;
							pscaninfo->data_cnt = 0;
							wifi_station_scan(NULL, json_scan_cb);
						} else {
							strstr ++;

							if (os_strncmp(strstr, "page", 4) == 0) {
								if (pscaninfo != NULL) {
									pscaninfo->pagenum = *(strstr + 5);
									pscaninfo->pagenum -= 0x30;
									if (pscaninfo->pagenum > pscaninfo->totalpage || pscaninfo->pagenum == 0) {
										response_send(ptrespconn, false);
									} else {
										json_send(ptrespconn, SCAN);
									}
								} else {
									response_send(ptrespconn, false);
								}
							} else if(os_strncmp(strstr, "finish", 6) == 0){
								bss_temp = bss_head;
								while(bss_temp != NULL) {
									bss_head = bss_temp->next.stqe_next;
									os_free(bss_temp);
									bss_temp = bss_head;
								}
								bss_head = NULL;
								bss_temp = NULL;
								response_send(ptrespconn, true);
							} else {
								response_send(ptrespconn, false);
							}
						}
					} else {
						response_send(ptrespconn, false);
					}
				}else if (os_strcmp(pURL_Frame->pSelect, "upgrade") == 0 &&
    					os_strcmp(pURL_Frame->pCommand, "command") == 0) {
    					if (os_strcmp(pURL_Frame->pFilename, "getuser") == 0) {
    						json_send(ptrespconn , USER_BIN);
    			}
                }else{
//                    response_send(ptrespconn, false);
                	json_send(ptrespconn , INDEX);
                }

                break;

            case POST:
                os_printf("We have a POST request.\n");
                pParseBuffer = (char *)os_strstr(precvbuffer, "\r\n\r\n");

                if (pParseBuffer == NULL) {
                    break;
                }

                pParseBuffer += 4;
                if (os_strcmp(pURL_Frame->pSelect, "config") == 0 &&
                        os_strcmp(pURL_Frame->pCommand, "command") == 0) {
                	if (os_strcmp(pURL_Frame->pFilename, "wifi") == 0) {
                        if (pParseBuffer != NULL) {
                            response_send(ptrespconn, true);
                            wifi_set(ptrespconn, pParseBuffer);
                        } else {
                            response_send(ptrespconn, false);
                        }
                    }else
					if (os_strcmp(pURL_Frame->pFilename, "smartconfig") == 0) {
						response_send(ptrespconn, true);
						os_printf("Smartconfig\r\n");
						Smart_flag=1;
						os_timer_disarm(&app_upgrade_10s);
						os_timer_setfn(&app_upgrade_10s,(os_timer_func_t *)smartcfg_cb, NULL);
						os_timer_arm(&app_upgrade_10s, 1000, 0);
					}else
					if (os_strcmp(pURL_Frame->pFilename, "APmode") == 0) {
						response_send(ptrespconn, true);
						Server_Mode = AP_MODE;
						spi_flash_erase_sector(0x79 + 2);
						spi_flash_write((0x79 + 2) * 4096,(uint32 *)&Server_Mode, sizeof(Server_Mode));

						os_timer_disarm(&app_upgrade_10s);
						os_timer_setfn(&app_upgrade_10s,(os_timer_func_t *)apmode_cb, NULL);
						os_timer_arm(&app_upgrade_10s, 1000, 0);
					}else
                    if (os_strcmp(pURL_Frame->pFilename, "reset") == 0) {
                            response_send(ptrespconn, true);

    						os_timer_disarm(&app_upgrade_10s);
    						os_timer_setfn(&app_upgrade_10s,(os_timer_func_t *)reset_cb, NULL);
    						os_timer_arm(&app_upgrade_10s, 1000, 0);
                    }else
					if (os_strcmp(pURL_Frame->pFilename, "wifimode") == 0) {
							response_send(ptrespconn, true);
							os_timer_disarm(&app_upgrade_10s);
							os_timer_setfn(&app_upgrade_10s,(os_timer_func_t *)wifimode_cb, NULL);
							os_timer_arm(&app_upgrade_10s, 1000, 0);
					}else
					if (os_strcmp(pURL_Frame->pFilename, "mqttmode") == 0) {
							response_send(ptrespconn, true);
							os_timer_disarm(&app_upgrade_10s);
							os_timer_setfn(&app_upgrade_10s,(os_timer_func_t *)mqttmode_cb, NULL);
							os_timer_arm(&app_upgrade_10s, 1000, 0);
					}else {
                        response_send(ptrespconn, false);
                    }
                }else
				if(os_strcmp(pURL_Frame->pSelect, "upgrade") == 0 &&
					    os_strcmp(pURL_Frame->pCommand, "command") == 0){
					if (os_strcmp(pURL_Frame->pFilename, "start") == 0){
						upgrade_lock = 1;
						system_upgrade_init();
						system_upgrade_flag_set(UPGRADE_FLAG_START);
						os_timer_disarm(&upgrade_check_timer);
						os_timer_setfn(&upgrade_check_timer, (os_timer_func_t *)upgrade_check_func, NULL);
						os_timer_arm(&upgrade_check_timer, 120000, 0);

						response_send(ptrespconn, true);
						os_printf("local upgrade start\n");

				        uart0_sendStr("Upgrade start.\r\n\r\n\r\n");

					} else if (os_strcmp(pURL_Frame->pFilename, "reset") == 0) {
						response_send(ptrespconn, true);

						os_printf("local upgrade restart\n");

						os_timer_disarm(&app_upgrade_10s);
						os_timer_setfn(&app_upgrade_10s,(os_timer_func_t *) upgrade_finish, NULL);
						os_timer_arm(&app_upgrade_10s, 1000, 0);
					} else {
						response_send(ptrespconn, false);
					}
				}else {
					response_send(ptrespconn, false);
                }
                 break;
        }

        if (precvbuffer != NULL){
        	os_free(precvbuffer);
        	precvbuffer = NULL;
        }
        os_free(pURL_Frame);
        pURL_Frame = NULL;
#if Client_Num == 1
        if(holdnum)
        {
            espconn_recv_unhold(ptrespconn);
            holdnum = false;
        }
#else
        if((holdnum&(0x01<<i))>>i)
        {
        	holdnum^=(0x01<<i);
            espconn_recv_unhold(ptrespconn);
        }
#endif
        if(upgrade_lock == 0)
        	iscommand = false;
        _temp_exit:
            ;
    }
    else if(upgrade_lock == 1){
//    	uart0_sendStr(pusrdata);
    	local_upgrade_download(ptrespconn,pusrdata, length);
		if (precvbuffer != NULL){
			os_free(precvbuffer);
			precvbuffer = NULL;
		}
		os_free(pURL_Frame);
		pURL_Frame = NULL;
#if Client_Num == 1
        if(holdnum)
        {
            espconn_recv_unhold(ptrespconn);
            holdnum = false;
        }
#else
        if((holdnum&(0x01<<i))>>i)
        {
        	holdnum^=(0x01<<i);
            espconn_recv_unhold(ptrespconn);
        }
#endif
    }
}

