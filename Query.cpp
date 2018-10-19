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
            throw domain_error("Prijata zprava oznamuje chybovy stav");

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

Record Query::GetAnswer(uint8_t id)
{
    return answers_[id];
}

unsigned long Query::GetAnswerCount()
{
    return answers_.size();
}