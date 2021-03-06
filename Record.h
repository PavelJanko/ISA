#ifndef IPK_LOOKUP_RECORD_H
#define IPK_LOOKUP_RECORD_H

#include <cstring>
#include <ios>
#include <iomanip>
#include <sstream>
#include "Question.h"

// Trida pro zpracovani prijatych zprav
class Record {
    private:
        std::string name_;
        uint8_t type_;
        uint8_t rclass_;
        uint32_t ttl_;
        std::string rdata_;

        void ParseIPv4(unsigned char buffer[1024], uint16_t * buffer_offset);
        void ParseIPv6(unsigned char buffer[1024], uint16_t * buffer_offset);
        void ParseName(std::string * data_holder, unsigned char buffer[1024], uint16_t * buffer_offset, uint16_t data_len);
        void ParseHexKey(uint16_t loop_from, uint16_t data_len, unsigned char buffer[1024], uint16_t *buffer_offset);
        // Funkce slouzi k pripojeni zadaneho poctu octetu za textovy format odpovedi
        void AppendOctet(uint32_t * rr_helper, uint8_t octet_count, unsigned char buffer[1024], uint16_t * buffer_offset);

    public:
        Record(unsigned char buffer[1024], uint16_t * buffer_offset);
        std::string GetData();
        std::string GetName();
        std::string GetType();
};

#endif