#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <stdlib.h>
#include <combaseapi.h>
#include <vector>
#include<chrono>
#include <ctime>
#include <iomanip>
#include <iomanip>

#include "ip.h"
#include "icmp.h"

using namespace std;

const USHORT MAX_PACKET = 1024; //Максимальный размер ICMP пакета

const USHORT ICMP_ECHO = 8;

const USHORT NUMBER_PACKETS = 4;
const USHORT RESP_TIMEOUT = 4000;
const USHORT REQ_TIMEOUT = 1000;
const USHORT TTL = 2;


USHORT CURRENT_CK_SUM = 0;
GUID CorrentGuid;

struct SendedPacket
{
    int seq;
    bool received;
    chrono::steady_clock::time_point sendTime;
    GUID guid;
};

// Получить временной интервал в миллисекундах
int GetDeltaTime(chrono::steady_clock::time_point startInterval)
{
    auto now = chrono::steady_clock::now();
    auto deltaTime = chrono::duration_cast<chrono::milliseconds>(now - startInterval).count();

    return deltaTime;
}

_Put_time<char> GetTime()
{
    auto now_sys = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now_sys);
    tm *tm = localtime(&t);
    _Put_time<char> time = put_time(tm, "%H:%M:%S");

    return time;
}

// True если все пакеты приняты или таймауты истекли
bool IsResponceTimeout(vector<SendedPacket> &packets)
{
    bool allTimeout = true;

    for(SendedPacket &packet : packets)
    {
        if(packet.received)
            continue;

        auto deltaTime = GetDeltaTime(packet.sendTime);
        if(deltaTime >= RESP_TIMEOUT)
        {
            packet.received = true;
            cout << "Packet " << packet.seq << " timeout! at " << GetTime() << "\n";

            continue;
        }
        allTimeout = false;
    }
    return allTimeout;
}

// Вычислить 16-битную комплиментарную сумму
// для указанного буфера с заголовком
USHORT checksum(USHORT *buffer, int size)
{
    unsigned long cksum = 0;

    while(size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if(size)
    {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum >>16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    CURRENT_CK_SUM = (USHORT)(~cksum);
    return (USHORT)(~cksum);
}


void FillICMPData(char *icmp_packet, int dataSize, int packetNumber)
{
    IcmpHeader *icmp_hdr = nullptr;
    icmp_hdr = (IcmpHeader*)icmp_packet;
    IcmpData *icmp_data_block = (IcmpData*)(icmp_packet + sizeof(IcmpHeader));

    icmp_hdr->i_type = ICMP_ECHO;
    icmp_hdr->i_code = 0;
    //icmp_hdr->i_id = (USHORT)GetCurrentProcessId();
    icmp_hdr->i_cksum = 0;
    //icmp_hdr->i_seq = packetNumber;

    //cmp_data_block->timestamp = GetTickCount();
    icmp_data_block->guid = CorrentGuid;

    icmp_hdr->i_cksum = checksum((USHORT*)icmp_packet, dataSize);
}

bool ValidateArgs(int argc, char **argv)
{
    if(argc != 2)
    {
        cerr << "[ERROR] Invalid number of arguments\n";
        return false;
    }

    sockaddr_in sa;
    if(inet_pton(AF_INET, argv[1], &(sa.sin_addr)) != 1)
    {
        cerr << "[ERROR] Invalid IP adress\n";
        return false;
    }

    return true;
}

void DecodeICMP(char *buf, int bufSize, vector<SendedPacket> &sendedPackets)
{
    IpHeader *ip_hdr = NULL;
    IcmpHeader *icmp_hdr = NULL;
    IcmpData *icmp_data = NULL;

    ip_hdr = (IpHeader*)buf;

    USHORT iphdrlen = ip_hdr->h_len * 4;
    auto icmpHeadLen = sizeof(IcmpHeader);

    icmp_hdr = (IcmpHeader*)(buf + iphdrlen);
    icmp_data = (IcmpData*)(buf + iphdrlen + sizeof(IcmpHeader));

    if(icmp_hdr->i_type != 0 || icmp_hdr->i_code != 0 )
    {
        IpHeader *error_ip_hdr = NULL;
        IcmpData *error_icmp_data = NULL;

        error_ip_hdr = (IpHeader*)(buf + iphdrlen + sizeof(IcmpHeader));
        USHORT error_ip_hdr_len = error_ip_hdr->h_len * 4;
        error_icmp_data = (IcmpData*)(buf + iphdrlen + sizeof(IcmpHeader)+ error_ip_hdr_len + sizeof(IcmpHeader));

        auto errorsizeIP = sizeof(error_ip_hdr);

        for(SendedPacket &sp : sendedPackets)
        {
            if(!sp.received && sp.guid == error_icmp_data->guid)
            {
                auto deltaTime = GetDeltaTime(sp.sendTime);
                cout << "\n" << "ERROR Reply for packet "
                     //<< icmp_hdr->i_seq
                     << " time=" << deltaTime << "ms"
                     << " Type:" << (USHORT)icmp_hdr->i_type
                     << " Code:" << (USHORT)icmp_hdr->i_code
                     << " TTL:" << (USHORT)ip_hdr->ttl
                     << "\n" << endl;

                sp.received = true;
            }
        }
    }
    else
    {
        for(SendedPacket &sp : sendedPackets)
        {
            if(!sp.received && sp.guid == icmp_data->guid)
            {
                auto deltaTime = GetDeltaTime(sp.sendTime);
                cout << "\n" << "Reply for packet "
                     //<< icmp_hdr->i_seq
                     << " time=" << deltaTime << "ms"
                     << " Type:" << (USHORT)icmp_hdr->i_type
                     << " Code:" << (USHORT)icmp_hdr->i_code
                     << " TTL:" << (USHORT)ip_hdr->ttl
                     << "\n"<< endl;

                sp.received = true;
            }
        }
    }

}

void CleanResources(SOCKET &sockRaw, char *icmp_data, char *recvbuf)
{
    if(sockRaw != INVALID_SOCKET)
        closesocket(sockRaw);

    HeapFree(GetProcessHeap(), 0, icmp_data);
    HeapFree(GetProcessHeap(), 0, recvbuf);

    WSACleanup();
}



int main(int argc, char *argv[])
{
    struct sockaddr_in dest, src;
    char *icmp_packet = NULL, *recvbuf = NULL;

    bool isValidate = ValidateArgs(argc, argv);
    if(!isValidate)
        return -1;

    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
    {
        cerr << "[ERROR] WSAStartup() failed: " << WSAGetLastError() << "\n";
        return -1;
    }

    SOCKET sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockRaw == INVALID_SOCKET)
    {
        cerr << "[ERROR] socket() failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        return -1;
    }

    setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char*)&TTL, sizeof(TTL));

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &(dest.sin_addr.s_addr));

    int datasize = sizeof(IcmpHeader) + sizeof(IcmpData);
    icmp_packet = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PACKET);
    recvbuf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PACKET);

    vector<SendedPacket> sendedPackets;
    auto lastSendTime = chrono::steady_clock::now();

    fd_set fds;
    struct timeval tv;
    int ret, srclen = sizeof(src);

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    int nCount = 0;
    while (1)
    {
        if(sendedPackets.size() < NUMBER_PACKETS && GetDeltaTime(lastSendTime) >= REQ_TIMEOUT)
        {
            CoCreateGuid(&CorrentGuid);
            FillICMPData(icmp_packet, datasize, nCount);

            int bwrote = sendto(sockRaw, icmp_packet, datasize, 0, (sockaddr*)&dest, sizeof(dest));
            if(bwrote == SOCKET_ERROR)
            {
                if(WSAGetLastError() == WSAETIMEDOUT)
                {
                    cerr << "[ERROR] sendto time out\n";
                    continue;
                }
                cerr <<"[ERROR] sento() failed " << WSAGetLastError() << "\n";
                return -1;
            }
            else
            {
                SendedPacket sp;
                sp.received = false;
                sp.sendTime = chrono::steady_clock::now();
                sp.seq = nCount;
                sp.guid = CorrentGuid;
                sendedPackets.push_back(sp);

                lastSendTime = chrono::steady_clock::now();
                cout << "Packet " << nCount << " is send at " << GetTime() << "\n";

                ++nCount;
            }
        }

        FD_ZERO(&fds);
        FD_SET(sockRaw, &fds);

        ret = select(0, &fds, NULL, NULL, &tv);
        if(ret > 0)
        {
            int bufSize = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (sockaddr*)&src, &srclen);
            DecodeICMP(recvbuf, bufSize, sendedPackets);
        }
        else if(ret != 0)
        {
            cerr << "[ERROR] select is error " << WSAGetLastError() << "\n";
            CleanResources(sockRaw, icmp_packet, recvbuf);
        }

        if(IsResponceTimeout(sendedPackets) && sendedPackets.size() == NUMBER_PACKETS)
            break;


        Sleep(100);
    }

    CleanResources(sockRaw, icmp_packet, recvbuf);
    return 0;
}
