#ifndef IPK_LOOKUP_QUESTION_H
#define IPK_LOOKUP_QUESTION_H

#include <stdint-gcc.h>
#include <string>
#include <stdexcept>
#include <arpa/inet.h>

// Vycet typu dotazu, ktere program podporuje
enum QuestionType
{
    QTYPE_A = 1,
    QTYPE_NS = 2,
    QTYPE_CNAME = 5,
    QTYPE_SOA = 6,
    QTYPE_MX = 15,
    QTYPE_TXT = 16,
    QTYPE_AAAA = 28
};

// Struktura pro ulozeni typu a tridy otazky do dotazu
struct Question {
    private:
        uint16_t question_type : 16;
        uint16_t question_class : 16;

    public:
        QuestionType GetType();
};

#endif
