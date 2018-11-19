#include <iostream>
#include <getopt.h>
#include <pcap.h>
#include <chrono>
#include <syslog.h>
#include <unistd.h>
#include <netdb.h>
#include <csignal>
#include "Query.h"

#define PROTOCOL_NUMBER_OFFSET 9
#define DESTINATION_IP_OFFSET 16
#define UDP_PROTOCOL_NUMBER 17

#define UDP_HEADER_SIZE 8

#define DEFAULT_CALC_TIME 60
#define MAX_SYSLOG_MSG_LEN 1024

using namespace std;

vector<string> responses_;

string CutOutResponse(string response) {
    return response.substr(response.find("- - - "), response.find_last_of(' ') - response.find("- - - "));
}

void SignalCallback(int sig_number) {
    if (sig_number == SIGUSR1) {
        for (auto &response : responses_)
            cout << response.substr(response.find("- - - ") + 6, string::npos);
    }
}

void PrintHelp(bool arg_error = false) {
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
        cout << "ERROR (ARGUMENT): Chybny format nebo kombinace vstupnich argumentu." << endl;
        exit(1);
    }

    exit(0);
}

void PacketReceived(u_char *interface_name, const struct pcap_pkthdr *packet_header, const u_char *packet_buffer) {
    int mac_header_size = 14;

    // Pokud neni specifikovan interface, velikost ramce se meni
    if (!strcmp((char *) interface_name, "any"))
        mac_header_size = 16;

    int ipHeaderLength = (packet_buffer[mac_header_size] & 0x0f) * 4;
    int protocolNumber = packet_buffer[mac_header_size + PROTOCOL_NUMBER_OFFSET];

    string local_ip;
    for (int i = 0; i < 4; i++) {
        local_ip.append(to_string(packet_buffer[mac_header_size + DESTINATION_IP_OFFSET + i]));
        if (i != 3)
            local_ip.append(1, '.');
    }

    int dns_offset = 0;

    // Delky UDP a TCP paketu se lisi a tomu je treba prizpusobit kalkulaci pozice DNS casti
    if (protocolNumber == UDP_PROTOCOL_NUMBER)
        dns_offset = mac_header_size + ipHeaderLength + UDP_HEADER_SIZE;

    // Vzhledem k tomu, ze jsem neresil fragmentaci, jsem se rozhodl implementaci TCP preskocit
    else
        return;

    try {
        Query query(&packet_buffer[dns_offset]);

        if (query.GetAnswerCount() != 0) {
            // Zpracovani odpovedi
            for (uint8_t i = 0; i < query.GetAnswerCount(); i++) {
                Record output = query.GetAnswer(i);

                char timeBuffer[64];
                strftime(timeBuffer, sizeof(timeBuffer), "%FT%T.", localtime(&packet_header->ts.tv_sec));

                stringstream response;
                response << "<134>1 " << timeBuffer
                         << std::setfill('0') << std::setw(3)
                         << packet_header->ts.tv_usec / 1000 << "Z " << local_ip << " dns-export - - - "
                         << output.GetName() << " " << output.GetType() << " " << output.GetData() << " 1" << endl;

                if (responses_.empty())
                    responses_.push_back(response.str());
                else {
                    /*
                     * Pokud se jiz identicka odpoved vyskytuje v seznamu odpovedi, tak se odpovedi slouci
                     * a inkrementuje se pole "count" na konci odpovedi
                     */
                    bool found_match = false;

                    for (auto &prev_response : responses_) {
                        if (CutOutResponse(prev_response) == CutOutResponse(response.str())) {
                            uint8_t prev_count = (uint8_t) stoi(
                                    prev_response.substr(prev_response.find_last_of(' ') + 1, prev_response.length())
                            );

                            if (prev_response.substr(0, prev_response.find("- - -")) !=
                                response.str().substr(0, response.str().find("- - -"))) {
                                prev_response = prev_response.substr(0, prev_response.find_last_of(' ') + 1);
                                prev_response.append(to_string(++prev_count) + "\n");
                            }

                            found_match = true;
                            break;
                        }
                    }

                    if (!found_match)
                        responses_.push_back(response.str());
                }
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
    bool h_flag = false, c_flag = false;
    string pcap_file_name, interface_name, syslog_address;
    chrono::seconds calc_time_offset = chrono::seconds(DEFAULT_CALC_TIME);
    chrono::time_point<chrono::system_clock> calc_time =
            chrono::system_clock::now() + calc_time_offset;

    // Zpracovani argumentu
    while (optind < argc && !h_flag) {
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
                        c_flag = true;
                        calc_time_offset = chrono::seconds(stoi(optarg));
                        calc_time = chrono::system_clock::now() + calc_time_offset;
                    } catch (...) {
                        PrintHelp(true);
                    } break;
                case 'h':
                    h_flag = true;
                    break;
                default:
                    PrintHelp(true);
            }
        } else {
            h_flag = true;
            break;
        }
    }

    // Kontrola spravne kombinace vstupnich argumentu
    if ((!pcap_file_name.empty() && !interface_name.empty()) || (!pcap_file_name.empty() && c_flag))
        PrintHelp(true);

    else if (h_flag)
        PrintHelp();

    else if (pcap_file_name.empty() && interface_name.empty())
        return 0;

    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_exp;
    bpf_u_int32 ip_address;
    pcap_t *handle;

    // Zpracovava se bud soubor formatu pcap nebo se odchytava vsechen provoz na rozhrani
    if (!pcap_file_name.empty())
        handle = pcap_open_offline(pcap_file_name.c_str(), error_buffer);
    else {
        handle = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, error_buffer);

        /*
        * Pokud je specifikovan nazev pcap souboru, program vypise po zpracovani souboru export na STDOUT,
        * v opacnem pripade vypisuje statistky pri zachyceni signalu SIGUSR1.
        */
        signal(SIGUSR1, SignalCallback);
    }

    try {
        // Pro odposlech je potreba mit patricna opravneni
        if (handle == nullptr)
            throw runtime_error("Nepodarilo se otevrit zarizeni zadane zarizeni nebo soubor pro odposlech");

        // Kompilace a nastaveni filtru
        if (pcap_compile(handle, &filter_exp, "port 53", 0, ip_address) == -1)
            throw runtime_error("Nepodarilo se zpracovat zadany filtr");

        if (pcap_setfilter(handle, &filter_exp) == -1)
            throw runtime_error("Nepodarilo se nastavit filtr");
    } catch (runtime_error &e) {
        cerr << "ERROR (RUNTIME): " << e.what() << endl;
        return 2;
    }

    // Nastaveni neblokujici komunikace, at lze korektne vypsat statistiky po uplynuti casu v pripade prace s rozhranim
    pcap_setnonblock(handle, 1, error_buffer);

    while (true) {
        if (!pcap_file_name.empty())
            pcap_loop(handle, -1, PacketReceived, (u_char *) interface_name.c_str());
        else {
            while (chrono::system_clock::now() < calc_time)
                pcap_dispatch(handle, -1, PacketReceived, (u_char *) interface_name.c_str());

            calc_time += calc_time_offset;
        }

        if (!syslog_address.empty()) {
            int conn_socket = 0;

            try {
                // Vytvoreni socketu pro komunikaci se syslog serverem
                if ((conn_socket = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
                    throw runtime_error("Nepodarilo se vytvorit socket pro komunikaci");

                sockaddr_in server_address_ipv4;
                bzero(&server_address_ipv4, sizeof(server_address_ipv4));
                server_address_ipv4.sin_family = AF_INET;
                server_address_ipv4.sin_port = htons(514);

                sockaddr_in6 server_address_ipv6;

                /*
                 * Prvne se pokousi prevest argument adressy na IPv4 format, pote na IPv6 a naposled se pokousi
                 * argument zpracovat jako hostname a ziskat z nej adresu.
                 */
                if (inet_pton(AF_INET, syslog_address.c_str(), &(server_address_ipv4.sin_addr)) == 1) {
                    if (connect(conn_socket, (struct sockaddr *) &server_address_ipv4, sizeof(server_address_ipv4)) ==
                        -1)
                        throw runtime_error("Nepodarilo se pripojit k syslog serveru");
                    else {
                        bzero(&server_address_ipv6, sizeof(server_address_ipv6));
                        server_address_ipv6.sin6_family = AF_INET6;
                        server_address_ipv6.sin6_port = htons(514);
                    }
                } else if (inet_pton(AF_INET6, syslog_address.c_str(), &(server_address_ipv6.sin6_addr)) == 1) {
                    if (connect(conn_socket, (struct sockaddr *) &server_address_ipv6, sizeof(server_address_ipv6)) ==
                        -1)
                        throw runtime_error("Nepodarilo se pripojit k syslog serveru");
                } else {
                    hostent *addressFromHost = gethostbyname(syslog_address.c_str());

                    if (addressFromHost != nullptr) {
                        memcpy(&server_address_ipv4.sin_addr, addressFromHost->h_addr_list[0],
                               (size_t) addressFromHost->h_length);
                        if (connect(conn_socket, (struct sockaddr *) &server_address_ipv4,
                                    sizeof(server_address_ipv4)) ==
                            -1)
                            throw runtime_error("Nepodarilo se pripojit k syslog serveru");
                    } else
                        throw invalid_argument("Zadana adresa syslog serveru neni platna");
                }

                // Pokud je velikost nekolika po sobe jdoucich zprav mensi nez 1 kB, tak se zpravy slouci
                for (int i = 0; i < responses_.size(); i++) {
                    while (i + 1 < responses_.size() &&
                           responses_[i].size() + responses_[i + 1].size() < MAX_SYSLOG_MSG_LEN) {
                        responses_[i + 1].insert(0, responses_[i]);
                        i++;
                    }

                    // Odeslani zpravy na syslog server
                    write(conn_socket, responses_[i].data(), responses_[i].size());
                }

                if (!pcap_file_name.empty())
                    break;
            } catch (runtime_error &e) {
                cerr << "ERROR (RUNTIME): " << e.what() << endl;
                return 2;
            } catch (invalid_argument &e) {
                cerr << "ERROR (ARGUMENT): " << e.what() << endl;
                PrintHelp(true);
            }
        }

        // Pokud je zadan pcap soubor a neni zadana syslog adresa, vypise se vystup na STDOUT
        else {
            SignalCallback(SIGUSR1);

            if (!pcap_file_name.empty())
                break;
        }
    }

    return 0;
}
