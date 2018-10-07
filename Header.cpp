#include "Header.h"

Header::Header() {
    static uint16_t count = 0;
    id = htons(++count);
    qr = 0;
    opcode = 0;
    aa = tc = 0;
    rd = 0;
    ra = z = 0;
    rcode = 0;
    qdcount = htons(1);
    ancount = nscount = arcount = 0;
}

int Header::GetTransactionId() {
    return id;
}

int Header::GetType() {
    return qr;
}

int Header::GetAdditionalCount() {
    return ntohs(arcount);
}

int Header::GetAnswerCount() {
    return ntohs(ancount);
}

int Header::GetAuthNSCount() {
    return ntohs(nscount);
}

int Header::GetResponseCode() {
    return rcode;
}

void Header::SetFlags(unsigned char buffer[512]) {
    uint16_t formatting_helper = 0;
    memcpy(&formatting_helper, buffer + 2, sizeof(formatting_helper));
    formatting_helper = ntohs(formatting_helper);

    // AND se provadi podle pozice bitu ve zprave specifikovane RFC 1035
    qr = (formatting_helper & 32768) >> 15;
    tc = formatting_helper & 512;
    rcode = formatting_helper & 15;
}