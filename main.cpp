#include <iostream>
#include <getopt.h>
#include <pcap.h>
#include <chrono>
#include <future>
#include "Query.h"

#define PROTOCOL_NUMBER_OFFSET 9
#define UDP_PROTOCOL_NUMBER 17

#define TCP_HEADER_SIZE_OFFSET 12
#define UDP_HEADER_SIZE 8

using namespace std;

void print_help(bool arg_error = false)
{
    cout << "Pouziti: ./dns-export [-h]" << endl
         << "         ./dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]" << endl
         << "Popis parametru:" << endl
         << "    h (help) - volitelny parametr, pri jeho zadani se vypise napoveda a program se ukonci" << endl
         << "    r (file.pcap) - volitelny parametr, pcap soubor, ktery se ma zpracovat" << endl
         << "    i (interface) - volitelny parametr, na kterem rozhrani se ma naslouchat na DNS provoz" << endl
         << "    s (syslog-server) - volitelny parametr, hostname (nebo IPv4/v6) adresa syslog serveru" << endl
         << "    t (seconds) - volitelny parametr, doba vypoctu statistik v sekundach, (vychozi hodnota 60 sekund)"
         << endl;

    if (arg_error) {
        cout << "ERROR (ARGUMENT): Chybny format vstupnich argumentu." << endl;
        exit(2);
    }

    exit(0);
}

void packetReceived(u_char *interface_name, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int mac_header_size = 14;

    if (!strcmp((char *)interface_name, "any"))
        mac_header_size = 16;
    
    int ipHeaderLength = (buffer[mac_header_size] & 0x0f) * 4;
    int protocolNumber = buffer[mac_header_size + PROTOCOL_NUMBER_OFFSET];
    int dnsOffset = 0;

    if (protocolNumber == UDP_PROTOCOL_NUMBER) {
        dnsOffset = mac_header_size + ipHeaderLength + UDP_HEADER_SIZE;
    } else {
        int tcpHeaderLength = ((buffer[mac_header_size + ipHeaderLength + TCP_HEADER_SIZE_OFFSET] & 0xf0) >> 4) * 4;
        cout << ipHeaderLength << "..." << tcpHeaderLength << endl;
        dnsOffset = mac_header_size + ipHeaderLength + tcpHeaderLength;
    }

    try {
        Query query(&buffer[dnsOffset]);

        if (query.GetAnswerCount() != 0) {
            // Zpracovani odpovedi
            for (uint8_t i = 0; i < query.GetAnswerCount(); i++) {
                Record output = query.GetAnswer(i);
                cout << "<134> dns-export - - - " << output.GetName() << " " << output.GetType() << " "
                     << output.GetData() << endl;

//                if (i == query.GetAnswerCount() - 1)
//                    throw runtime_error("Nepodarilo se zjistit informace k zadanemu nazvu nebo zadane adrese");
            }
        }
    } catch (const runtime_error &e) {
        cerr << "ERROR (RUNTIME): " << e.what() << endl;
    } catch (const invalid_argument &e) {
        cerr << "ERROR (ARGUMENT): " << e.what() << endl;
    } catch (const domain_error &e) {}
}

int main(int argc, char *argv[]) {
    int c = 0;
    int calcTime = 60;
    bool hFlag = false;
    string pcap_file_name, interface_name, syslog_address;

    // Zpracovani argumentu
    while (optind < argc && !hFlag) {
        if ((c = getopt(argc, argv, ":r:i:s:t:h")) != -1 && (c == 'h' || optarg)) {
            switch (c) {
                case 'r':
                    pcap_file_name.assign(optarg);
                    break;
                case 'i':
                    interface_name.assign(optarg);
                    break;
                case 's':
                    syslog_address.assign(optarg);
                    break;
                case 't':
                    try {
                        calcTime = stoi(optarg);
                    } catch (...) {
                        print_help(true);
                    } break;
                case 'h':
                    hFlag = true;
                    break;
                default:
                    print_help(true);
            }
        } else {
            hFlag = true;
            break;
        }
    }

    // Kontrola spravne kombinace vstupnich argumentu
    if ((!pcap_file_name.empty() && !interface_name.empty()))
        print_help(true);

    // Vypis pomoci k programu
    else if (hFlag)
        print_help();

    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_exp;
    bpf_u_int32 ip_address;

    if (interface_name.empty())
        handle = pcap_open_offline(pcap_file_name.c_str(), error_buffer);
    else
        handle = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, error_buffer);

    try {
        if (handle == nullptr)
            throw runtime_error("Nepodarilo se otevrit zarizeni zadane zarizeni pro odposlech");

        if (pcap_compile(handle, &filter_exp, "port 53", 0, ip_address) == -1)
            throw runtime_error("Nepodarilo se zpracovat zadany filtr");

        if (pcap_setfilter(handle, &filter_exp) == -1)
            throw runtime_error("Nepodarilo se nastavit filtr");
    } catch (runtime_error &e) {
        cerr << "ERROR (RUNTIME): " << e.what() << endl;
    }

//    future<int> timer = async (sleepInSeconds, calcTime);
    pcap_loop(handle, -1, packetReceived, (u_char *)interface_name.c_str());
    
    return 0;
}