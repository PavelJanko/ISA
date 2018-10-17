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
#define UDP_PROTOCOL_NUMBER 17

#define TCP_HEADER_SIZE_OFFSET 12
#define UDP_HEADER_SIZE 8

#define DEFAULT_CALC_TIME 60

using namespace std;

vector<string> responses_;

string CutOutResponse(string response) {
    return response.substr(response.find("- - - "), response.find_last_of(' ') - response.find("- - - "));
}

void SignalCallback(int sig_number) {
    for (auto &response : responses_)
        cout << response;
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
        cout << "ERROR (ARGUMENT): Chybny format vstupnich argumentu." << endl;
        exit(1);
    }

    exit(0);
}

void PacketReceived(u_char *interface_name, const struct pcap_pkthdr *packet_header, const u_char *packet_buffer) {
    int mac_header_size = 14;

    if (!strcmp((char *) interface_name, "any"))
        mac_header_size = 16;

    int ipHeaderLength = (packet_buffer[mac_header_size] & 0x0f) * 4;
    int protocolNumber = packet_buffer[mac_header_size + PROTOCOL_NUMBER_OFFSET];
    int dnsOffset = 0;

    if (protocolNumber == UDP_PROTOCOL_NUMBER)
        dnsOffset = mac_header_size + ipHeaderLength + UDP_HEADER_SIZE;
    else {
        int tcpHeaderLength =
                ((packet_buffer[mac_header_size + ipHeaderLength + TCP_HEADER_SIZE_OFFSET] & 0xf0) >> 4) * 4;
        dnsOffset = mac_header_size + ipHeaderLength + tcpHeaderLength;
    }

    try {
        Query query(&packet_buffer[dnsOffset]);

        if (query.GetAnswerCount() != 0) {
            // Zpracovani odpovedi
            for (uint8_t i = 0; i < query.GetAnswerCount(); i++) {
                Record output = query.GetAnswer(i);

                stringstream response;
                response << "<134>1 " << put_time(std::localtime(&packet_header->ts.tv_sec), "%FT%T.")
                         << std::setfill('0') << std::setw(3)
                         << packet_header->ts.tv_usec / 1000 << "Z dns-export - - - " << output.GetName() << " "
                         << output.GetType() << " " << output.GetData() << " 1" << endl;

                if (responses_.empty())
                    responses_.push_back(response.str());
                else {
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
    chrono::time_point<chrono::system_clock> calc_time =
            chrono::system_clock::now() + chrono::seconds(DEFAULT_CALC_TIME);

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
                        calc_time = chrono::system_clock::now() + chrono::seconds(stoi(optarg));
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
    if (!pcap_file_name.empty() && c_flag)
        PrintHelp(true);

    // Vypis pomoci k programu
    else if (h_flag || (!pcap_file_name.empty() && !interface_name.empty()))
        PrintHelp();

    else if ((!pcap_file_name.empty() || !interface_name.empty()) && syslog_address.empty())
        signal(SIGUSR1, SignalCallback);

    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_exp;
    bpf_u_int32 ip_address;
    pcap_t *handle;

    if (interface_name.empty())
        handle = pcap_open_offline(pcap_file_name.c_str(), error_buffer);
    else
        handle = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, error_buffer);

    try {
        if (handle == nullptr)
            throw runtime_error("Nepodarilo se otevrit zarizeni zadane zarizeni nebo soubor pro odposlech");

        if (pcap_compile(handle, &filter_exp, "port 53", 0, ip_address) == -1)
            throw runtime_error("Nepodarilo se zpracovat zadany filtr");

        if (pcap_setfilter(handle, &filter_exp) == -1)
            throw runtime_error("Nepodarilo se nastavit filtr");
    } catch (runtime_error &e) {
        cerr << "ERROR (RUNTIME): " << e.what() << endl;
        return 2;
    }

    pcap_setnonblock(handle, 1, error_buffer);

    if (interface_name.empty())
        pcap_loop(handle, -1, PacketReceived, (u_char *) interface_name.c_str());
    else {
        while (chrono::system_clock::now() < calc_time)
            pcap_dispatch(handle, -1, PacketReceived, (u_char *) interface_name.c_str());
    }

    if (syslog_address.empty()) {
        SignalCallback(0);
        return 0;
    }

    int conn_socket = 0;

    try {
        if ((conn_socket = socket(PF_INET, SOCK_STREAM, 0)) < 0)
            throw runtime_error("Nepodarilo se vytvorit socket pro komunikaci");

        sockaddr_in server_address_ipv4;
        bzero(&server_address_ipv4, sizeof(server_address_ipv4));
        server_address_ipv4.sin_family = AF_INET;
        server_address_ipv4.sin_port = htons(514);
        
        sockaddr_in6 server_address_ipv6;
        bzero(&server_address_ipv6, sizeof(server_address_ipv6));
        server_address_ipv6.sin6_family = AF_INET6;
        server_address_ipv6.sin6_port = htons(514);

        // Prevod adresy z textove na binarni formu
        if (inet_pton(AF_INET, syslog_address.c_str(), &(server_address_ipv4.sin_addr)) == 1) {
            if (connect(conn_socket, (struct sockaddr *) &server_address_ipv4, sizeof(server_address_ipv4)) == -1)
                throw runtime_error("Nepodarilo se pripojit k syslog serveru");
        } else if (inet_pton(AF_INET6, syslog_address.c_str(), &(server_address_ipv6.sin6_addr)) == 1) {
            if (connect(conn_socket, (struct sockaddr *) &server_address_ipv6, sizeof(server_address_ipv6)) == -1)
                throw runtime_error("Nepodarilo se pripojit k syslog serveru");
        } else {
            hostent *addressFromHost = gethostbyname(syslog_address.c_str());

            if (addressFromHost != nullptr) {
                memcpy(&server_address_ipv4.sin_addr, addressFromHost->h_addr_list[0],
                       (size_t) addressFromHost->h_length);
                if (connect(conn_socket, (struct sockaddr *) &server_address_ipv4, sizeof(server_address_ipv4)) == -1)
                    throw runtime_error("Nepodarilo se pripojit k syslog serveru");
            } else
                throw invalid_argument("Zadana adresa syslog serveru neni platna");
        }

        for (auto &response : responses_)
            write(conn_socket, response.data(), response.size());
    } catch (runtime_error &e) {
        cerr << "ERROR (RUNTIME): " << e.what() << endl;
        return 2;
    } catch (invalid_argument &e) {
        cerr << "ERROR (ARGUMENT): " << e.what() << endl;
        PrintHelp(true);
    }

    return 0;
}