#ifndef IP_H
#define IP_H

#include <winsock2.h>

#pragma pack(1)

struct IpHeader
{
    unsigned char h_len:4; //Длина заголовка
    unsigned char version:4; //Версия IP
    unsigned char tos; //Тип службы
    unsigned short total_len; //Полный размер пакета
    unsigned short ident; //Уникальный идентификатор
    unsigned short frag_and_flags; //флаги
    unsigned char ttl; //Время жизни
    unsigned char proto; //Протокол (TCP, udp)
    unsigned short checksum; //контрольная сумма

    unsigned int sourceIP;
    unsigned int destIP;
};

#pragma pack()

#endif // IP_H
