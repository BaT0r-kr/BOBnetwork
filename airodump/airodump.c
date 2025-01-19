/******************************************************************************
 *  Compile:  gcc -o airodump airodump.c -lpthread
 *  Usage:    sudo ./airodump mon0
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <errno.h>

#define MAX_CHANNEL 14  // 최대 채널 개수
#define HOP_INTERVAL 1  // 채널 전환 주기(초)
#define MAX_AP_LIST 256 // 저장 가능한 최대 AP 개수

// AP 정보를 저장하는 구조체
typedef struct _ap_info
{
    unsigned char bssid[6]; // BSSID (MAC 주소)
    char essid[33];         // ESSID (최대 32바이트 + NULL)
    int beacon_count;       // 비콘 프레임 수신 횟수
    int pwr;                // 신호 세기(dBm)
} ap_info;

static ap_info g_ap_list[MAX_AP_LIST]; // AP 정보를 저장하는 리스트
static int g_ap_count = 0;             // 현재 저장된 AP 개수
static char g_iface[IFNAMSIZ] = {0};   // 무선 인터페이스 이름
static int g_stop_hopping = 0;         // 채널 호핑 중지 플래그
static int g_current_channel = 1;      // 현재 채널 번호

// BSSID를 문자열 형식(XX:XX:XX:XX:XX:XX)으로 변환하는 함수
void bssid_to_str(unsigned char *bssid, char *str, size_t size)
{
    snprintf(str, size, "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2],
             bssid[3], bssid[4], bssid[5]);
}

// AP 리스트에서 BSSID를 찾아 반환하거나, 없으면 새로 추가하는 함수
ap_info *find_or_insert_ap(unsigned char *bssid)
{
    for (int i = 0; i < g_ap_count; i++)
    {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0)
            return &g_ap_list[i];
    }
    if (g_ap_count < MAX_AP_LIST)
    {
        ap_info *new_ap = &g_ap_list[g_ap_count++];
        memset(new_ap, 0, sizeof(ap_info));
        memcpy(new_ap->bssid, bssid, 6);
        strcpy(new_ap->essid, "<unknown>");
        return new_ap;
    }
    return NULL; // 리스트가 가득 찼을 경우 NULL 반환
}

// 주기적으로 채널을 변경하는 쓰레드 함수
void *channel_hopper(void *arg)
{
    int channel = 1;
    char cmd[128];

    while (!g_stop_hopping)
    {
        snprintf(cmd, sizeof(cmd), "iw dev %s set channel %d", g_iface, channel);
        system(cmd); // 시스템 명령어 실행하여 채널 변경
        g_current_channel = channel;
        channel = (channel % MAX_CHANNEL) + 1;
        sleep(HOP_INTERVAL);
    }
    pthread_exit(NULL);
}

// Radiotap 헤더를 분석하여 신호 세기(RSSI)를 추출하는 함수
int parse_radiotap_header(const unsigned char *packet, int *dbm_signal)
{
    unsigned short radiotap_len = packet[2] + (packet[3] << 8);
    *dbm_signal = (radiotap_len > 22) ? (int)((signed char)packet[22]) : 0;
    return radiotap_len;
}

// 802.11 Beacon 프레임을 분석하여 AP 정보를 업데이트하는 함수
void parse_beacon_frame(const unsigned char *ieee80211, int length, int dbm_signal)
{
    const unsigned char *bssid = &ieee80211[16];
    ap_info *ap = find_or_insert_ap((unsigned char *)bssid);
    if (!ap)
        return;

    ap->pwr = dbm_signal;
    ap->beacon_count++;

    int offset = 24 + 12; // 802.11 헤더(24바이트) + Fixed Param(12바이트)
    while (offset + 2 < length)
    {
        unsigned char tag_number = ieee80211[offset];
        unsigned char tag_len = ieee80211[offset + 1];
        offset += 2;
        if (offset + tag_len > length)
            break;

        if (tag_number == 0)
        { // SSID 태그
            memset(ap->essid, 0, sizeof(ap->essid));
            if (tag_len > 0 && tag_len < sizeof(ap->essid))
            {
                memcpy(ap->essid, &ieee80211[offset], tag_len);
                ap->essid[tag_len] = '\0';
            }
            else
            {
                strcpy(ap->essid, "<hidden>");
            }
            break;
        }
        offset += tag_len;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return -1;
    }
    strncpy(g_iface, argv[1], IFNAMSIZ - 1);

    // Raw 소켓 생성
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("socket");
        return -1;
    }

    // 인터페이스 인덱스 가져오기
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, g_iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl-SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }

    // 소켓 바인딩
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        perror("bind");
        close(sockfd);
        return -1;
    }

    // 채널 호핑 쓰레드 시작
    pthread_t tid;
    if (pthread_create(&tid, NULL, channel_hopper, NULL) != 0)
    {
        perror("pthread_create");
        close(sockfd);
        return -1;
    }

    unsigned char buffer[2048];

    while (1)
    {
        ssize_t n = recv(sockfd, buffer, sizeof(buffer), 0);
        if (n <= 0)
        {
            perror("recv");
            break;
        }
        if (n < 36)
            continue;

        // Radiotap 헤더 분석 및 신호 세기(RSSI) 추출
        int dbm_signal = 0;
        int radiotap_len = parse_radiotap_header(buffer, &dbm_signal);
        if (radiotap_len < 0 || radiotap_len > n)
            continue;

        // 802.11 헤더 시작 지점
        const unsigned char *ieee80211 = buffer + radiotap_len;
        int ieee80211_len = n - radiotap_len;
        if (ieee80211_len < 24)
            continue;

        unsigned char frame_control = ieee80211[0];
        unsigned char type = (frame_control & 0x0C) >> 2;
        unsigned char subtype = (frame_control & 0xF0) >> 4;

        if (type == 0 && subtype == 8)
        { // Beacon 프레임 처리
            parse_beacon_frame(ieee80211, ieee80211_len, dbm_signal);

            system("clear");
            printf("[ Channel Hopping: Current Channel = %d ]\n", g_current_channel);
            printf(" BSSID              PWR   Beacons   ESSID\n");
            printf("-----------------------------------------------\n");
            for (int i = 0; i < g_ap_count; i++)
            {
                char bssid_str[18];
                bssid_to_str(g_ap_list[i].bssid, bssid_str, sizeof(bssid_str));
                printf(" %-17s  %-4d  %-8d  %s\n",
                       bssid_str, g_ap_list[i].pwr, g_ap_list[i].beacon_count, g_ap_list[i].essid);
            }
        }
    }

    g_stop_hopping = 1;
    pthread_join(tid, NULL);
    close(sockfd);
    return 0;
}
