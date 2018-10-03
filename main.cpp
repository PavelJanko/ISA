#include <iostream>
#include <getopt.h>

using namespace std;

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
    } else if (hFlag)
        return 2;

    cout << "Got here!" << endl;
}
