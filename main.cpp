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
const USHORT TTL = 255;


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


void FillICMPData(IcmpPacket *pkt)
{
    pkt->header.i_type = ICMP_ECHO;
    pkt->header.i_code = 0;
    pkt->data.guid = CorrentGuid;
    pkt->header.i_cksum =0;

    pkt->header.i_cksum = checksum((USHORT*)pkt, sizeof(IcmpPacket));
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

void PrintHexDump(const vector<char> &data, int len, int bytes_per_line = 16) {
    std::cout << std::hex << std::setfill('0');
    for (int i = 0; i < len; i += bytes_per_line) {
        // Печать смещения
        std::cout << std::setw(4) << i << "   ";

        // Печать шестнадцатеричных байтов
        for (int j = 0; j < bytes_per_line; ++j) {
            if (i + j < len) {
                std::cout << std::setw(2) << (unsigned int)(unsigned char)data[i + j] << " ";
            } else {
                std::cout << "   "; // для выравнивания, если последняя строка короче
            }
        }

        // // Печать ASCII представления
        // std::cout << " ";
        // for (int j = 0; j < bytes_per_line && i + j < len; ++j) {
        //     char c = data[i + j];
        //     std::cout << (isprint(c) ? c : '.');
        // }
        std::cout << std::endl;
    }
    std::cout << std::dec; // вернуть десятичный формат
}

std::string GuidToString(const GUID& guid) {
    wchar_t wbuf[64];
    if (StringFromGUID2(guid, wbuf, 64) == 0)
        return "{}";
    // Преобразование широкой строки в узкую (подходит для ASCII-символов GUID)
    char buf[64];
    wcstombs(buf, wbuf, 64);
    return std::string(buf);
}

void DecodeICMP(vector<char> &data, int bufSize, vector<SendedPacket> &sendedPackets)
{
    const char* buf = data.data();

    cout << "\n" << "Input packet "
         << " size=" << bufSize
         << "\n" << endl;
    //PrintHexDump(data, bufSize);

    IpHeader *ip_hdr = NULL;
    IcmpHeader *icmp_hdr = NULL;
    IcmpData *icmp_data = NULL;

    ip_hdr = (IpHeader*)buf;

    USHORT iphdrlen = ip_hdr->h_len * 4;
    auto icmpHeadLen = sizeof(IcmpHeader);
    auto sumsize = iphdrlen + sizeof(IcmpHeader);
    if(iphdrlen + sizeof(IcmpHeader) > bufSize)
    {
        cout << "input packet is small\n" << endl;
        return;
    }

    icmp_hdr = (IcmpHeader*)(buf + iphdrlen);
    icmp_data = (IcmpData*)(buf + iphdrlen + sizeof(IcmpHeader));


    if(icmp_hdr->i_type != 0 || icmp_hdr->i_code != 0 )
    {
        IpHeader *error_ip_hdr = NULL;
        IcmpData *error_icmp_data = NULL;

        error_ip_hdr = (IpHeader*)(buf + iphdrlen + sizeof(IcmpHeader) + 4);
        USHORT error_ip_hdr_len = error_ip_hdr->h_len * 4;
        error_icmp_data = (IcmpData*)(buf + iphdrlen + sizeof(IcmpHeader) + 4 + error_ip_hdr_len + sizeof(IcmpHeader));

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
                     << "\n"
                     << " inputGuid " << GuidToString(error_icmp_data->guid) << "\n"
                    // << " outputGuid" <<  outputGuid
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
                wchar_t outputGuid[64];
                StringFromGUID2(sp.guid, outputGuid, 64);

                auto deltaTime = GetDeltaTime(sp.sendTime);
                cout << "\n" << "Reply for packet "
                     //<< icmp_hdr->i_seq
                     << " time=" << deltaTime << "ms"
                     << " Type:" << (USHORT)icmp_hdr->i_type
                     << " Code:" << (USHORT)icmp_hdr->i_code
                     << " TTL:" << (USHORT)ip_hdr->ttl
                     << "\n"
                     << " inputGuid  " << GuidToString(icmp_data->guid) << "\n"
                     //<< " outputGuid " << outputGuid
                     << "\n" << endl;


                sp.received = true;
            }
        }
    }

}

void CleanResources(SOCKET &sockRaw)
{
    if(sockRaw != INVALID_SOCKET)
        closesocket(sockRaw);


    WSACleanup();
}

int CreateSocket(SOCKET &sockRaw)
{
    u_long mode = 1;
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
    {
        cerr << "[ERROR] WSAStartup() failed: " << WSAGetLastError() << "\n";
        return -1;
    }

    sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockRaw == INVALID_SOCKET)
    {
        cerr << "[ERROR] socket() failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        return -1;
    }

    setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char*)&TTL, sizeof(TTL));

    int nonBlock = ioctlsocket(sockRaw, FIONBIO, &mode);
    if(nonBlock == SOCKET_ERROR)
    {
        if(sockRaw != INVALID_SOCKET)
            closesocket(sockRaw);

        WSACleanup();
    }
    return 1;
}



int main(int argc, char *argv[])
{
    struct sockaddr_in dest, src;
    //char *icmp_packet = NULL, *recvbuf = NULL;

    bool isValidate = ValidateArgs(argc, argv);
    if(!isValidate)
        return -1;

    SOCKET sockRaw;
    CreateSocket(sockRaw);

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &(dest.sin_addr.s_addr));

    int datasize = sizeof(IcmpPacket);

    //recvbuf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PACKET);
    vector<char> recvbuf(MAX_PACKET, 0);
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

            IcmpPacket icmp_pack;
            FillICMPData((IcmpPacket*)&icmp_pack);

            int bwrote = sendto(sockRaw, (char*)&icmp_pack, sizeof(IcmpPacket), 0, (sockaddr*)&dest, sizeof(dest));

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
                cout << "Packet " << nCount
                     << " is send at " << GetTime()
                     << " Size " << bwrote
                     << "\n"
                     << "GUID " << GuidToString(CorrentGuid)
                     << "\n" << endl;

                //PrintHexDump(&icmp_pack, sizeof(IcmpPacket));

                cout << "sizeof(IcmpPacket) " << sizeof(IcmpPacket) << "\n"
                     << "sizeof(icmp_pack)" << sizeof(icmp_pack) << "\n"
                     << "sizeof(sp.guid)" << sizeof(sp.guid)
                     << "\n";

                ++nCount;
            }
        }
        //continue;
        FD_ZERO(&fds);
        FD_SET(sockRaw, &fds);

        ret = select(0, &fds, NULL, NULL, &tv);
        if(ret > 0)
        {
            if(FD_ISSET(sockRaw, &fds))
            {
                while(1)
                {
                    int bufSize = recvfrom(sockRaw, recvbuf.data(), recvbuf.size(), 0, (sockaddr*)&src, &srclen);
                    if(bufSize < 0)
                    {
                        if(WSAGetLastError() == WSAEWOULDBLOCK)
                            break;
                    }

                    DecodeICMP(recvbuf, bufSize, sendedPackets);
                }
            }
            else
            {
                cout << "NOT FDISSET" << "\n";
            }
        }
        else if(ret != 0)
        {
            cerr << "[ERROR] select is error " << WSAGetLastError() << "\n";
            CleanResources(sockRaw);
        }

        if(IsResponceTimeout(sendedPackets) && sendedPackets.size() == NUMBER_PACKETS)
            break;


        Sleep(100);
    }

    CleanResources(sockRaw);
    return 0;
}
