#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <endian.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/*
1. 해시 맵을 이용해서, beacon 카운트 및 bssid 중복 처리
2. 출력은 값이 업데이트 될때마다 말고, 쓰레드를 이용해서 출력
3. 
*/

struct radiotap_header {
    uint8_t  Header_reveision;
    uint8_t  Header_pad;
    uint16_t Header_length;
    uint32_t Present_flags;
    uint64_t MAC_timestamp;
    uint8_t  Flags;
    uint8_t  Data_Rate;
    uint16_t Channel_frequency;
    uint16_t Channel_flags;
    int8_t  Antenna_signal; // # 2
    uint8_t  Antenna;
    uint16_t RX_flags;
} __attribute__((packed));

struct beacon_frame {
    uint16_t Frame_Control_Field;
    uint16_t Duration_;
    uint8_t  Receiver_address[6];
    uint8_t  Transmitter_address[6];
    uint8_t  BSS_Id[6]; // # 1
    uint16_t Fragment_Sequence_number;
} __attribute__((packed));

struct fixed_parameter {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capability_info;
} __attribute__((packed));

struct packet_info {
    uint8_t  BSSID[6];
    int8_t  PWR;
    uint8_t Beacons;
    uint8_t Data;
    uint8_t s;
    uint8_t CH;
    uint8_t MB;
    uint8_t ENC;
    uint8_t CIPHER;
    uint8_t AUTH;
    uint8_t ESSID[100];
} PacketInfo;

struct packet_info aps[100];
uint8_t ap_count = 0;

uint8_t current_channel = 1; // 현재 채널
char *interface;         // 무선 인터페이스 이름
time_t start_time;

void channel_hopper() {
    static int group_offset = 0; // 그룹 내 오프셋
    
    // 각 그룹의 기본값: 1, 5, 11
    int base_channels[3] = {1, 5, 11};
    int group_size = 4; // 각 그룹의 크기 (1-4, 5-9, 11-13, ...) 

    // 현재 그룹 계산
    int group = group_offset % 3; // 0, 1, 2 중 하나
    
    // 현재 채널 계산: 기본값 + 현재 오프셋
    current_channel = base_channels[group] + (group_offset / 3) % group_size;

    // 오프셋 증가
    group_offset = (group_offset + 1) % (group_size * 3); // 전체 순환 구조 유지

    // 채널 변경 명령 실행
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "iwconfig %s channel %d", interface, current_channel);
    system(cmd);

    // printf("Switched to channel %d\n", current_channel);

    // sleep(1); // 간격 대기
}

// Function to parse tagged parameters into packet_info
void parse_tagged_parameters(uint8_t *tagged_parameters, uint16_t length) {
    size_t offset = 0;

    while (offset < length) {
        if (offset + 2 > length) {
           break;
        }
        
        uint8_t tag_num = tagged_parameters[offset];
        uint8_t tag_len = tagged_parameters[offset + 1];

        // BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID
        switch (tag_num) {
            case 0x00: // ESSID
                memcpy(PacketInfo.ESSID, &tagged_parameters[offset + 2], tag_len);
                PacketInfo.ESSID[tag_len] = '\0'; // Null-terminate
                // printf("%s\n", PacketInfo.ESSID);
                break;

            case 0x03: // Channel (CH)
                PacketInfo.CH = tagged_parameters[offset + 2];
                // printf("%d\n", PacketInfo.CH);
                break;

            case 0x01: // Supported Rates (MB - Maximum Bitrate)
                if (tag_len > 0) {
                    uint8_t max_rate = 0;
                    for (uint8_t i = 0; i < tag_len; i++) {
                        if (tagged_parameters[offset + 2 + i] > max_rate) {
                            max_rate = tagged_parameters[offset + 2 + i];
                        }
                    }
                    if (max_rate / 2 > PacketInfo.MB)
                        PacketInfo.MB = max_rate / 2; // Convert to Mbps
                }
                break;
            
            case 0x32: // Supported Rates (MB - Maximum Bitrate)
                if (tag_len > 0) {
                    uint8_t max_rate = 0;
                    for (uint8_t i = 0; i < tag_len; i++) {
                        if (tagged_parameters[offset + 2 + i] > max_rate) {
                            max_rate = tagged_parameters[offset + 2 + i];
                        }
                    }
                    PacketInfo.MB = max_rate / 2; // Convert to Mbps
                }
                break;

            case 0x30: // RSN Information (ENC, CIPHER, AUTH)
                if (tag_len >= 4) {
                    // Extract encryption type (ENC)
                    PacketInfo.ENC = 2; // Assuming WPA2

                    // Extract cipher suite (CIPHER)
                    uint8_t cipher_offset = offset + 1 + 1 + 2 + 4 + 2; // Pairwise Cipher Suite starts at offset 8
                    if (cipher_offset < length) {
                        uint8_t PCS_Type = tagged_parameters[cipher_offset + 3];
                        // printf("%02x\n", PCS_Type);
                        if (PCS_Type == 0x04) {
                            PacketInfo.CIPHER = 1; // CCMP (AES)
                        } else if (PCS_Type == 0x02) {
                            PacketInfo.CIPHER = 2; // TKIP
                        } else {
                            PacketInfo.CIPHER = 0; // Unknown
                        }
                    }

                    // Extract authentication type (AUTH)
                    uint8_t auth_offset = cipher_offset + 4 + 2; // AKM Suite starts at offset 14
                    if (auth_offset < length) {
                        uint8_t AKM_Type = tagged_parameters[auth_offset + 3];
                        // printf("%02x\n", AKM_Type);
                        if (AKM_Type == 0x02) {
                            PacketInfo.AUTH = 1; // PSK
                        } else if (AKM_Type == 0x01) {
                            PacketInfo.AUTH = 2; // EAP
                        } else {
                            PacketInfo.AUTH = 0; // Unknown
                        }
                    }
                    printf("%d %d %d\n", PacketInfo.ENC, PacketInfo.CIPHER, PacketInfo.AUTH);
                }
                break;
            
            default:
                // printf("Unknown Tag Number: %u, Length: %u\n", tag_num, tag_len);
                break;
        }

        // Move to the next tagged parameter
        offset += 1 + 1 + tag_len;
    }
}

// Function to check if a BSSID and ESSID combination is already in the array
int is_duplicate(uint8_t *BSSID, const char *ESSID) {
    for (int i = 0; i < ap_count; i++) {
        if (memcmp(aps[i].BSSID, BSSID, 6) == 0 && strcmp(aps[i].ESSID, ESSID) == 0) {
            return i; // Return index of the matching AP
        }
    }
    return -1; // No match found
}

int airodump_print(uint8_t ch, struct packet_info *PacketInfo) {
    time_t now = time(NULL);             // 현재 시간 가져오기
    struct tm *local = localtime(&now); // 로컬 시간으로 변환

    if (local == NULL) {
        perror("localtime");
        return 1;
    }
    // clear screen
    printf("\033[2J");

    // move curser (1, 1)
    printf("\033[%d;%dH", 1, 1);

    time_t end_time = time(NULL);
    int8_t cal_time = (int8_t)(end_time - start_time);

    if (cal_time > 60) {
        printf("[ CH %2d ][ Elapsed: %d mins ][ %04d-%02d-%02d %02d:%02d:%02d ]\n\n", 
        ch,
        (int8_t)(cal_time / 60),
        // 시간 출력: YYYY-MM-DD HH:MM 형식
        local->tm_year + 1900, // 연도는 1900을 더해야 실제 연도가 됨
        local->tm_mon + 1,    // 월은 0부터 시작하므로 1을 더해야 함
        local->tm_mday,       // 일
        local->tm_hour,       // 시
        local->tm_min,
        local->tm_sec);
    } else {
        printf("[ CH %2d ][ Elapsed: %d s ][ %04d-%02d-%02d %02d:%02d:%02d ]\n\n", 
        ch,
        cal_time,
        // 시간 출력: YYYY-MM-DD HH:MM 형식
        local->tm_year + 1900, // 연도는 1900을 더해야 실제 연도가 됨
        local->tm_mon + 1,    // 월은 0부터 시작하므로 1을 더해야 함
        local->tm_mday,       // 일
        local->tm_hour,       // 시
        local->tm_min,
        local->tm_sec);
    }
    
    printf(" BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID\n\n");

    for (int i = ap_count - 1; i >= 0; i--) {
        printf(" %02x:%02x:%02x:%02x:%02x:%02x  %d  %7d    %5d  %3d  %2d  %3d   %-4s %-4s   %-4s %s\n",
            aps[i].BSSID[0], aps[i].BSSID[1], aps[i].BSSID[2], aps[i].BSSID[3], aps[i].BSSID[4], aps[i].BSSID[5],
            aps[i].PWR,     // PWR
            aps[i].Beacons, // Beacons
            0,              // #Data,
            0,              // #/s
            aps[i].CH,      // CH
            aps[i].MB,              // MB
            aps[i].ENC    == 2 ? "WPA2" : "????", // ENC
            aps[i].CIPHER == 1 ? "AES" : (aps[i].CIPHER == 2 ? "TKIP" : "????"), // CIPHER
            aps[i].AUTH   == 1 ? "PSK" : (aps[i].AUTH   == 2 ? "EAP" : "????"), // AUTH
            aps[i].ESSID);  // ESSID
    }
};

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;

    start_time = time(NULL);

    // Check if device name is provided
    if (argc < 2) {
        fprintf(stderr, "syntax : %s <interface>\n", argv[0]);
        fprintf(stderr, "sample : %s mon0\n", argv[0]);
        return 1;
    }

    char *dev = argv[1]; /* Use the device name from argv[1] */
    interface = dev;

    // Open the session in promiscuous mode
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Grab a packets.
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) {
            /* Timeout occurred */
            continue;
        }

        // printf("Captured packet: len=%d, caplen=%d\n", header->len, header->caplen);

        // Parse packet.
        struct radiotap_header *radiotap_header = (struct radiotap_header *)packet;

        // uint8_t now_ch = (htole16(radiotap_header->Channel_frequency) - 2412) / 5 + 1;

		struct beacon_frame *beacon_frame = (struct beacon_frame *)(packet + radiotap_header->Header_length);
        
        if (beacon_frame->Frame_Control_Field != 0x0080)
            continue;

        struct fixed_parameter *fp = (struct fixed_parameter *)(packet + radiotap_header->Header_length 
                                                                       + sizeof(struct beacon_frame));

        uint8_t *tagged_parameters = (uint8_t *)(packet + radiotap_header->Header_length 
                                                        + sizeof(struct beacon_frame) 
                                                        + sizeof(struct fixed_parameter));

        uint8_t tagged_parameter_len = header->caplen - (radiotap_header->Header_length 
                                                         + sizeof(struct beacon_frame) 
                                                         + sizeof(struct fixed_parameter));

        // Parse pixed_parameter.
        // BSSID
        memset(&PacketInfo, 0, sizeof(PacketInfo));
        memcpy(PacketInfo.BSSID, beacon_frame->BSS_Id, 6);
        // PWR
        PacketInfo.PWR = radiotap_header->Antenna_signal;
        // Beacons
        // #Data
        // #/s
        // MB
        // ENC
        // CIPHER
        // AUTH

        // Parse tagged_parameter.
        parse_tagged_parameters(tagged_parameters, tagged_parameter_len);

        int index = is_duplicate(PacketInfo.BSSID, PacketInfo.ESSID);
        if (index >= 0) {
            aps[index].PWR = PacketInfo.PWR;
            aps[index].Beacons++;
        }else {
            if (ap_count < 100) {
                aps[ap_count] = PacketInfo;
                aps[ap_count].Beacons = 1;
                ap_count++;
            } else {
                fprintf(stderr, "AP list is full!\n");
            }
        }

        airodump_print(current_channel, &PacketInfo); // 쓰레드 처리 필요.
        // break; /* Exit after capturing the first packet */

        channel_hopper();
    }

    if (res == -1) {
        fprintf(stderr, "Error reading the packet: %s\n", pcap_geterr(handle));
    } else if (res == -2) {
        printf("No more packets to read from the file (EOF).\n");
    }

    /* Close the session */
    pcap_close(handle);

    return 0;
}
