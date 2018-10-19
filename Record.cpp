#include "Record.h"

Record::Record(unsigned char buffer[1024], uint16_t *buffer_offset) {
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

    // V pripade NS, TXT, CNAME a NSEC zaznamu jsou data odpovedi domenove jmeno
    else if (type_ == QuestionType::QTYPE_NS || type_ == QuestionType::QTYPE_TXT ||
             type_ == QuestionType::QTYPE_CNAME ||
             type_ == QuestionType::QTYPE_NSEC)
        this->ParseName(&rdata_, buffer, buffer_offset, data_len);

    // V pripade SOA a DNSSEC (krome NSEC) zaznamu jsou data odpovedi slozene z vice prvku
    else if (type_ == QuestionType::QTYPE_SOA) {
        uint32_t rr_helper = *buffer_offset;
        uint16_t prim_ns_length = *buffer_offset;

        // Zjisteni primarniho NS pro zonu
        this->ParseName(&rdata_, buffer, buffer_offset, data_len);
        rdata_.append(" ");
        *buffer_offset += 2;

        prim_ns_length = *buffer_offset - prim_ns_length;

        // Zjisteni e-mail adresy spravce
        this->ParseName(&rdata_, buffer, buffer_offset, data_len);
        rdata_.append(" ");
        *buffer_offset = rr_helper + prim_ns_length + (data_len - prim_ns_length - 20);

        rr_helper = 0;

        // Pote nasleduje 5 udaju kazdy o delce 4 oktety, jako napriklad seriove cislo, viz RFC 1035
        for (uint8_t i = 0; i < 5; i++)
            this->AppendOctet(&rr_helper, 4, buffer, buffer_offset);

        rdata_.insert(0, "\"");
        rdata_.insert(rdata_.length() - 1, "\"");
    } else if (type_ == QuestionType::QTYPE_DS) {
        uint32_t rr_helper = 0;

        // Zaznam zacina udaj o delce 2 oktety a pak 2 udaje po jednom oktetu
        this->AppendOctet(&rr_helper, 2, buffer, buffer_offset);
        this->AppendOctet(&rr_helper, 1, buffer, buffer_offset);
        this->AppendOctet(&rr_helper, 1, buffer, buffer_offset);

        // Zpracovani hexadecimalniho klice (prvni argument je suma delky predchozich sekci)
        this->ParseHexKey(4, data_len - 1, buffer, buffer_offset);

        rdata_.insert(0, "\"");
        rdata_.append("\"");
    } else if (type_ == QuestionType::QTYPE_RRSIG) {
        uint32_t rr_helper = 0;

        // Opet zpracovani nekolika polozek pred samotnym podpisovatelem a podpisem, viz RFC 4034
        this->AppendOctet(&rr_helper, 2, buffer, buffer_offset);
        this->AppendOctet(&rr_helper, 1, buffer, buffer_offset);
        this->AppendOctet(&rr_helper, 1, buffer, buffer_offset);
        this->AppendOctet(&rr_helper, 4, buffer, buffer_offset);
        this->AppendOctet(&rr_helper, 4, buffer, buffer_offset);
        this->AppendOctet(&rr_helper, 4, buffer, buffer_offset);
        this->AppendOctet(&rr_helper, 2, buffer, buffer_offset);

        // Zpracovani podpisovatele
        int sig_name_len = *buffer_offset;
        this->ParseName(&rdata_, buffer, buffer_offset, data_len);
        
        sig_name_len = *buffer_offset - sig_name_len;
        rdata_.append(" ");
        *buffer_offset -= 1;

        // Zpracovani podpisu
        this->ParseHexKey(18 + sig_name_len, data_len, buffer, buffer_offset);

        rdata_.insert(0, "\"");
        rdata_.append("\"");
    } else if (type_ == QTYPE_DNSKEY) {
        uint32_t rr_helper = 0;

        // Obdobne jako u DS zaznamu, opet polozky o celkove delce 4 oktety a nasledne klic
        this->AppendOctet(&rr_helper, 2, buffer, buffer_offset);
        this->AppendOctet(&rr_helper, 1, buffer, buffer_offset);
        this->AppendOctet(&rr_helper, 1, buffer, buffer_offset);

        this->ParseHexKey(4, data_len - 1, buffer, buffer_offset);

        rdata_.insert(0, "\"");
        rdata_.append("\"");
    } else
        throw std::domain_error("Byl prijat programem nezpracovatelny typ odpovedi");
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
    else if (type_ == QTYPE_DS)
        return "DS";
    else if (type_ == QTYPE_RRSIG)
        return "RRSIG";
    else if (type_ == QTYPE_NSEC)
        return "NSEC";
    return "DNSKEY";
}

std::string Record::GetData() {
    return rdata_;
}

void Record::ParseIPv4(unsigned char buffer[1024], uint16_t *buffer_offset) {
    for (int i = 0; i < 4; i++) {
        rdata_.append(std::to_string(buffer[*buffer_offset]));
        if (i != 3)
            rdata_.append(1, '.');
        *buffer_offset += 1;
    }
}

void Record::ParseIPv6(unsigned char buffer[1024], uint16_t *buffer_offset) {
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
Record::ParseName(std::string *data_holder, unsigned char buffer[1024], uint16_t *buffer_offset, uint16_t data_len) {
    uint16_t pointer_helper = 0;

    // Zjisteni pozice, na ktere se ma zacit odpoved cist
    if ((buffer[*buffer_offset] & 192) == 192) {
        memcpy(&pointer_helper, buffer + *buffer_offset, sizeof(pointer_helper));
        pointer_helper = htons(pointer_helper);
        pointer_helper = pointer_helper & 16383;
        *buffer_offset += 3;
    } else if ((buffer[*buffer_offset] & 192) == 0) {
        pointer_helper = *buffer_offset;

        // V pripade techto zaznamu se musi odsazeni bufferu dopocitat manualne        
        if (this->type_ != QTYPE_SOA && this->type_ != QTYPE_RRSIG)
            *buffer_offset += data_len;
    } else
        throw std::domain_error("Spatne zpracovana odpoved");

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

            if (this->type_ == QTYPE_SOA || this->type_ == QTYPE_RRSIG)
                *buffer_offset += 1;
        } else if (length == i) {
            data_holder->append(1, '.');
            length = 0;
            i = -1;
        } else {
            data_holder->append(1, buffer[pointer_helper]);
            pointer_helper++;

            if (this->type_ == QTYPE_SOA || this->type_ == QTYPE_RRSIG)
                *buffer_offset += 1;
        }
        j++;
    }
}

void Record::ParseHexKey(uint16_t loop_from, uint16_t data_len, unsigned char buffer[1024], uint16_t *buffer_offset) {
    while (loop_from <= data_len) {
        data_len--;

        std::stringstream int_to_hex;
        int_to_hex << std::setfill('0') << std::setw(2) << std::hex << (int) buffer[*buffer_offset];
        rdata_.append(int_to_hex.str());
        *buffer_offset += 1;
    }
}

void Record::AppendOctet(uint32_t *rr_helper, uint8_t octet_count, unsigned char buffer[1024], uint16_t *buffer_offset) {
    *rr_helper = 0;
    memcpy(rr_helper, buffer + *buffer_offset, octet_count);

    if (octet_count == 2)
        *rr_helper = htons((uint16_t) *rr_helper);
    else if (octet_count == 4)
        *rr_helper = htonl(*rr_helper);

    rdata_.append(std::to_string(*rr_helper));
    rdata_.append(" ");
    *buffer_offset += octet_count;
}