#ifndef IPK_LOOKUP_QUERY_H
#define IPK_LOOKUP_QUERY_H

#define DNS_PORT 53

#include <sys/socket.h>
#include <cstring>
#include <vector>
#include <algorithm>
#include "Header.h"
#include "Question.h"
#include "Record.h"

// Trida pro odesilani dotazu a prijimani odpovedi, rovnez obsahuje metody pro ziskani vysledku techto metod
class Query {
    private:
        Header header_;
        Question question_;
        std::vector<Record> answers_;
        std::vector<Record> auth_nss_;
        std::vector<Record> additional_;
        sockaddr_in dns_server_address_;
        std::string hostname_or_ip_;
        int32_t query_socket_;
        unsigned char buffer[512];
        uint16_t buffer_offset_ = 0;

        void ParseIPv4();
        void ParseIPv6();
        void TranslateHost();

    public:
        explicit Query(const u_char * packet_received);
        Record GetFirstAdditional();
        Record GetAnswer(uint8_t id);
        Record GetFirstAuthNS();
        unsigned long GetAnswerCount();
};

#endif
