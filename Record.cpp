#include "Record.h"

Record::Record(unsigned char buffer[512], uint16_t *buffer_offset) {
    type_ = 0;

    // Offsety se nastavuji podle RFC 1035
    this->ParseName(&name_, buffer, buffer_offset, 0);

    if (name_.empty())
        *buffer_offset += 2;

    type_ = buffer[*buffer_offset];
    *buffer_offset += 2;
    rclass_ = buffer[*buffer_offset];
    *buffer_offset += 1;
    memcpy(&ttl_, buffer + *buffer_offset, sizeof(ttl_));
    ttl_ = htonl(ttl_);
    *buffer_offset += 4;

    uint16_t data_len = 0;
    memcpy(&data_len, buffer + *buffer_offset, sizeof(data_len));
    data_len = htons(data_len);
    *buffer_offset += 2;

    // Pokud byl dotaz typu A, tak jsou data odpovedi IPv4 adresa
    if (type_ == QuestionType::QTYPE_A) {
        if (data_len == 4)
            this->ParseIPv4(buffer, buffer_offset);
        else
            throw std::runtime_error("Byla prijata IPv4 adresa o delce ruzne od 4");
    }

    // Pokud byl dotaz typu AAAA, tak jsou data odpovedi IPv6 adresa
    else if (type_ == QuestionType::QTYPE_AAAA) {
        if (data_len == 16)
            this->ParseIPv6(buffer, buffer_offset);
        else
            throw std::runtime_error("Byla prijata IPv6 adresa o delce ruzne od 16");
    }

    // Ve vsech ostatnich pripadech jsou data odpovedi domenove jmeno
    else if (type_ == QuestionType::QTYPE_NS || type_ == QuestionType::QTYPE_TXT ||
             type_ == QuestionType::QTYPE_CNAME || type_ == QuestionType::QTYPE_SOA ||
             type_ == QuestionType::QTYPE_NSEC)
        this->ParseName(&rdata_, buffer, buffer_offset, data_len);
    else if (type_ == QuestionType::QTYPE_RRSIG) {
        *buffer_offset += 18;
        int sigNameLength = *buffer_offset;

        this->ParseName(&rdata_, buffer, buffer_offset, data_len);

        sigNameLength = *buffer_offset - sigNameLength;
        rdata_.clear();
        *buffer_offset -= 1;

        while (18 + sigNameLength <= data_len) {
            data_len--;

            std::stringstream int_to_hex;
            int_to_hex << std::setfill('0') << std::setw(2) << std::hex << (int)buffer[*buffer_offset];
            rdata_.append(int_to_hex.str());
            *buffer_offset += 1;
        }
    }
    else
        throw std::runtime_error("Byl prijat programem nezpracovatelny typ odpovedi");
}

std::string Record::GetName() {
    return name_;
}

std::string Record::GetType() {
    if (type_ == QTYPE_A)
        return "A";
    else if (type_ == QTYPE_NS)
        return "NS";
    else if (type_ == QTYPE_CNAME)
        return "CNAME";
    else if (type_ == QTYPE_SOA)
        return "SOA";
    else if (type_ == QTYPE_MX)
        return "MX";
    else if (type_ == QTYPE_TXT)
        return "TXT";
    else if (type_ == QTYPE_AAAA)
        return "AAAA";
    else if (type_ == QTYPE_RRSIG)
        return "RRSIG";
    return "NSEC";
}

std::string Record::GetData() {
    return rdata_;
}

void Record::ParseIPv4(unsigned char buffer[512], uint16_t *buffer_offset) {
    for (int i = 0; i < 4; i++) {
        rdata_.append(std::to_string(buffer[*buffer_offset]));
        if (i != 3)
            rdata_.append(1, '.');
        *buffer_offset += 1;
    }
}

void Record::ParseIPv6(unsigned char buffer[512], uint16_t *buffer_offset) {
    uint16_t ipv6_helper = 0;

    // Pro prevod z IPv6 do textove podoby je zapotrebi jednotlive dvojice oktetu prevadet z hexadecimalni podoby na retezec
    for (int i = 0; i < 8; i++) {
        memcpy(&ipv6_helper, buffer + *buffer_offset, sizeof(ipv6_helper));
        ipv6_helper = htons(ipv6_helper);

        if (ipv6_helper != 0) {
            std::stringstream int_to_hex;
            int_to_hex << std::hex << ipv6_helper;
            rdata_.append(int_to_hex.str());
        }

        if (i != 7 && rdata_.substr(rdata_.length() - 2) != "::")
            rdata_.append(1, ':');
        *buffer_offset += 2;
    }
}

void
Record::ParseName(std::string *data_holder, unsigned char buffer[512], uint16_t *buffer_offset, uint16_t data_len) {
    uint16_t pointer_helper = 0;

    // Zjisteni pozice, na ktere se ma zacit odpoved cist
    if ((buffer[*buffer_offset] & 192) == 192) {
        memcpy(&pointer_helper, buffer + *buffer_offset, sizeof(pointer_helper));
        pointer_helper = htons(pointer_helper);
        pointer_helper = pointer_helper & 16383;
        *buffer_offset += 3;
    } else if ((buffer[*buffer_offset] & 192) == 0) {
        pointer_helper = *buffer_offset;

        if (this->type_ != QTYPE_RRSIG)
            *buffer_offset += data_len;
    } else
        throw std::runtime_error("Error");

    uint8_t length = 0;
    int j = 0;

    // Bud se prida znak, a nebo se zanoruje hloubeji
    for (int i = 0; j == data_len || buffer[pointer_helper] != 0; i++) {
        if (length == 0) {
            if ((buffer[pointer_helper] & 192) == 192) {
                // Rekurzivni volani se pouzije v pripade, ze je navesti pouzito vicekrat
                this->ParseName(data_holder, buffer, &pointer_helper, data_len);
                break;
            }

            length = buffer[pointer_helper] + 1;
            pointer_helper++;

            if (this->type_ == QTYPE_RRSIG)
                *buffer_offset += 1;
        } else if (length == i) {
            data_holder->append(1, '.');
            length = 0;
            i = -1;
        } else {
            data_holder->append(1, buffer[pointer_helper]);
            pointer_helper++;

            if (this->type_ == QTYPE_RRSIG)
                *buffer_offset += 1;
        } j++;
    }
}