#pragma once
#include <cstdint>
namespace fmo {
struct Contact {
    uint32_t uid=0,relay_uid=0,first_seen=0,last_seen=0,receptions=0,last_stream=0;
    char callsign[13]{};
};
struct ContactBook {
    static constexpr unsigned capacity=64;
    Contact contacts[capacity]{};
    unsigned count=0;
    // Called only after decoded PCM was successfully played. This is a heard
    // log, not evidence of a reciprocal or cryptographically signed contact.
    bool heard(uint32_t uid,const char *call,uint32_t relay,uint32_t stream,uint32_t utc);
};
enum class BookLoad { Ready, Missing, Unavailable };
// Unavailable includes corruption: the caller must not overwrite that book.
BookLoad load_contact_book(ContactBook *book);
bool save_contact_book(const ContactBook &book);
}
