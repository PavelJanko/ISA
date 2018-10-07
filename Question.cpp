#include "Question.h"

QuestionType Question::GetType()
{
    return (QuestionType)ntohs(question_type);
}