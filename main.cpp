#include <iostream>
#include <getopt.h>
#include <pcap.h>
#include "Query.h"

#define MAC_HEADER_SIZE 14

#define PROTOCOL_NUMBER_OFFSET 9
#define UDP_PROTOCOL_NUMBER 17

#define TCP_HEADER_SIZE_OFFSET 12
#define UDP_HEADER_SIZE 8

using namespace std;

void packetReceived(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int ipHeaderLength = (buffer[MAC_HEADER_SIZE] & 0x0f) * 4;
    int protocolNumber = buffer[MAC_HEADER_SIZE + PROTOCOL_NUMBER_OFFSET];
    int dnsOffset = 0;

    if (protocolNumber == UDP_PROTOCOL_NUMBER) {
        dnsOffset = MAC_HEADER_SIZE + ipHeaderLength + UDP_HEADER_SIZE;
    } else {
        int tcpHeaderLength = ((buffer[MAC_HEADER_SIZE + ipHeaderLength + TCP_HEADER_SIZE_OFFSET] & 0xf0) >> 4) * 4;
        cout << ipHeaderLength << "..." << tcpHeaderLength << endl;
        dnsOffset = MAC_HEADER_SIZE + ipHeaderLength + tcpHeaderLength;
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
    }
}

int main(int argc, char *argv[]) {
    int c = 0;
    int calcTime = 60;
    bool hFlag = false;
    string pcapFileName, interfaceName, syslogAddress;

    // Zpracovani argumentu
    while (optind < argc && !hFlag) {
        if ((c = getopt(argc, argv, ":r:i:s:t:h")) != -1 && (c == 'h' || optarg)) {
            switch (c) {
                case 'r':
                    pcapFileName.assign(optarg);
                    break;
                case 'i':
                    interfaceName.assign(optarg);
                    break;
                case 's':
                    syslogAddress.assign(optarg);
                    break;
                case 't':
                    try {
                        calcTime = stoi(optarg);
                    } catch (...) {
                        return 2;
                    } break;
                case 'h':
                    hFlag = true;
                    break;
                default:
                    return 2;
            }
        } else {
            hFlag = true;
            break;
        }
    }

    // Vypsani pomoci k programu
    if (hFlag) {
        cout << "Pouziti: ./dns-export [-h]" << endl
             << "         ./dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]" << endl
             << "Popis parametru:" << endl
             << "    h (help) - volitelny parametr, pri jeho zadani se vypise napoveda a program se ukonci" << endl
             << "    r (file.pcap) - volitelny parametr, pcap soubor, ktery se ma zpracovat" << endl
             << "    i (interface) - volitelny parametr, na kterem rozhrani se ma naslouchat na DNS provoz" << endl
             << "    s (syslog-server) - volitelny parametr, hostname (nebo IPv4/v6) adresa syslog serveru" << endl
             << "    t (seconds) - volitelny parametr, doba vypoctu statistik v sekundach, (vychozi hodnota 60 sekund)"
             << endl;
        return 0;
    }

    pcap_t *handle;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filterExp;
    bpf_u_int32 net;

    handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errorBuffer);

    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interfaceName.c_str(), errorBuffer);
        return 2;
    }

    if (pcap_compile(handle, &filterExp, "port 53", 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &filterExp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, -1, packetReceived, nullptr);
    
    return 0;
}