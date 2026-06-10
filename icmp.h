#ifndef ICMP_H
#define ICMP_H

#include <winsock2.h>
#include <guiddef.h>

#pragma pack(1)

struct IcmpHeader
{
    BYTE i_type;
    BYTE i_code;
    USHORT i_cksum;
};

struct IcmpData
{
    GUID guid;
};

#pragma pack()

#endif // ICMP_H

