#include "Query.h"

using namespace std;

Query::Query(const u_char * packet_received)
{
    memcpy(buffer, packet_received, sizeof(buffer));

    uint16_t response_id = 0;
    memcpy(&response_id, buffer, sizeof(response_id));

    // Korektni nastaveni vlajek pro hlavicku prichozi zpravy
    memcpy(&header_, buffer, sizeof(Header));
    header_.SetFlags(buffer);
    buffer_offset_ += sizeof(Header);

    while (buffer[buffer_offset_] != 0)
        buffer_offset_ += buffer[buffer_offset_] + 1;

    buffer_offset_ += 5;

    if (header_.GetType() == 1) {
        if (header_.GetResponseCode() != 0)
            throw runtime_error("Prijata zprava oznamuje chybovy stav");

        // V pripade, ze byla prijata odpoved, tak nas zbytek zpravy nezajima (stejne by se zahazoval)
        if (header_.GetAnswerCount() != 0) {
            for (int i = 0; i < header_.GetAnswerCount(); i++) {
                Record record(buffer, &buffer_offset_);
                answers_.push_back(record);
            }
        } else {
            // Zpracovani autoritativnich jmennych serveru
            for (int i = 0; i < header_.GetAuthNSCount(); i++) {
                Record record(buffer, &buffer_offset_);
                auth_nss_.push_back(record);
            }

            // Zpracovani dodatecnych zaznamu
            for (int i = 0; i < header_.GetAdditionalCount(); i++) {
                Record record(buffer, &buffer_offset_);
                additional_.push_back(record);
            }
        }
    }
}

Record Query::GetFirstAdditional()
{
    return additional_[0];
}

Record Query::GetAnswer(uint8_t id)
{
    return answers_[id];
}

unsigned long Query::GetAnswerCount()
{
    return answers_.size();
}

Record Query::GetFirstAuthNS()
{
    return auth_nss_[0];
}

void Query::ParseIPv4()
{
    string replace_helper;
    size_t pos_start = 0;
    size_t prev_pos = 0;

    // Reverzace adresy a konkatenace arpa koncovky
    while ((pos_start = hostname_or_ip_.find('.', pos_start)) != string::npos) {
        if (prev_pos != 0)
            replace_helper.insert(0, ".");
        replace_helper.insert(0, hostname_or_ip_.substr(prev_pos, pos_start - prev_pos));
        prev_pos = ++pos_start;
    }

    replace_helper.insert(0, hostname_or_ip_.substr(prev_pos, hostname_or_ip_.length() - prev_pos) + '.');
    hostname_or_ip_ = replace_helper;
    hostname_or_ip_.append(".in-addr.arpa");
}

void Query::ParseIPv6()
{
    string replace_helper = hostname_or_ip_;
    size_t pos_start = 0;
    size_t prev_pos = 0;

    // Zpracovani IPv6 adresy po dvojicich oktetu (az po 16)
    reverse(replace_helper.begin(), replace_helper.end());
    while ((pos_start = replace_helper.find(':', pos_start)) != string::npos) {
        if (replace_helper.substr(prev_pos, pos_start - prev_pos).length() != 4) {
            if (prev_pos == pos_start)
                replace_helper.insert(pos_start, "0000:0000");
            else
                replace_helper.insert(pos_start, 4 - replace_helper.substr(prev_pos, pos_start - prev_pos).length(), '0');
            pos_start = 0;
            prev_pos = 0;
        } else
            prev_pos = ++pos_start;
    }

    replace_helper.erase(remove(replace_helper.begin(), replace_helper.end(), ':'), replace_helper.end());

    stringstream dot_helper;
    dot_helper << replace_helper[0];
    for (unsigned int i = 1; i < replace_helper.size(); i++) {
        dot_helper << '.' << replace_helper[i];
    }

    // Konkatenace IPv6 koncovky pro reverzni vyhledavani
    hostname_or_ip_ = dot_helper.str();
    hostname_or_ip_.append(".ip6.arpa");
}

void Query::TranslateHost()
{
    string replace_helper = hostname_or_ip_;
    size_t pos_start = 0;
    size_t prev_pos = 0;

    // Prelozeni adresy na formu sekvence popisu podle RFC 1035
    while ((pos_start = hostname_or_ip_.find('.', pos_start)) != string::npos) {
        char octet_number = (pos_start - prev_pos);
        if (prev_pos != 0)
            replace_helper[prev_pos] = octet_number;
        else {
            replace_helper.insert(0, " ");
            replace_helper[0] = octet_number;
        }
        prev_pos = ++pos_start;
    } hostname_or_ip_ = replace_helper;
}