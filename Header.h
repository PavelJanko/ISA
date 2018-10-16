#ifndef IPK_LOOKUP_HEADER_H
#define IPK_LOOKUP_HEADER_H

#include <stdint-gcc.h>
#include <arpa/inet.h>
#include <cstring>

// Struktura pro hlavicku DNS zpravy, jejiz jednotlive atributy a jejich delky jsou specifikovany RFC 1035
struct Header {
    private:
        uint16_t id : 16;
        uint8_t qr : 1;
        uint8_t opcode : 4;
        uint8_t aa : 1;
        uint8_t tc : 1;
        uint8_t rd : 1;
        uint8_t ra : 1;
        uint8_t z : 3;
        uint8_t rcode : 4;
        uint16_t qdcount : 16;
        uint16_t ancount : 16;
        uint16_t nscount : 16;
        uint16_t arcount : 16;

    public:
        Header();
        int GetTransactionId();
        int GetType();
        int GetResponseCode();
        int GetAdditionalCount();
        int GetAnswerCount();
        int GetAuthNSCount();

        // Funkce slouzi pro korektni nastaveni vlajek po prijeti zpravy
        void SetFlags(unsigned char buffer[1024]);
};

#endif
