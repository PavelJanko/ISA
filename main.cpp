#include <iostream>
#include <getopt.h>
#include <pcap.h>

using namespace std;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    cout << (int)packet[0] << "." << (int)packet[1] << "." << (int)packet[2] << "." << (int)packet[3] << endl;
}

int main(int argc, char *argv[])
{
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
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filterExp;
    bpf_u_int32 net;

    handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interfaceName.c_str(), errbuf);
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

    pcap_loop(handle, -1, got_packet, nullptr);
}
