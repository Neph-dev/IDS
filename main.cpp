#include <cstring>
#include <iostream>
#include <pcap.h>
#include <unordered_map>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <curl/curl.h>

std::ofstream packets_file;

const char* packets_file_path = std::getenv("PACKETS_FILE_PATH");
const std::string path = std::string(packets_file_path ? packets_file_path : "packets_file.txt");

const int PACKETS_TO_CAPTURE = 70;
const int SYN_THRESHOLD = 20;
const int TIME_WINDOW = 60; // in seconds

struct TCP_Packet_Count {
    int syn_count = 0;
    std::time_t first_syn_time = 0;
};

std::unordered_map<std::string, TCP_Packet_Count> packet_counts;

size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp) {
    const char **payload_text = (const char **)userp;

    if ((size == 0) || (nmemb == 0) || ((*payload_text) == nullptr)) {
        return 0;
    }

    size_t len = strlen(*payload_text);
    memcpy(ptr, *payload_text, len);
    *payload_text += len; // Move the pointer to the next part

    return len;
}

// Function to send email alert using libcurl
void send_email_alert(const std::string& src_ip, int syn_count, struct tcphdr *tcp_header) {
    CURL *curl;
    CURLcode res = CURLE_OK;

    const char* email_password = std::getenv("EMAIL_PASSWORD");
    const char* sender_email = std::getenv("SENDER_EMAIL");
    const char* receiver_email = std::getenv("RECEIVER_EMAIL");
    if (!email_password || !sender_email || !receiver_email) {
        std::cerr << "Error: one or multiple environment variable not set!" << std::endl;
        return;
    }

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.gmail.com:587");

        curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

        curl_easy_setopt(curl, CURLOPT_USERNAME, sender_email);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, email_password);

        // Set the sender email
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, sender_email);

        // Set the recipient email
        struct curl_slist *recipients = nullptr;
        recipients = curl_slist_append(recipients, receiver_email);
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

        // Email content
        std::string email_data =
            "To: " + std::string(receiver_email) + "\r\n"
            "From: " + std::string(sender_email) + "\r\n"
            "Subject: SYN Flood Detected from IP: " + src_ip + "\r\n"
            "Potential SYN flood detected.\r\n"
            "\r\n"
            "--------------------------------------------------\r\n"
            "IP address: " + src_ip + ".\r\n"
            "SYN Count: " + std::to_string(syn_count) + " under " + std::to_string(TIME_WINDOW) + "s.\r\n"
            "Source Port: " + std::to_string(ntohs(tcp_header->source)) + "\r\n"
            "Destination Port: " + std::to_string(ntohs(tcp_header->dest)) + "\r\n"
            "--------------------------------------------------\r\n";

        const char *payload_text = email_data.c_str();

        // Set up the read callback function to send the email body
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
        curl_easy_setopt(curl, CURLOPT_READDATA, &payload_text);

        // Enable upload mode to send the data
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        // Send the email
        res = curl_easy_perform(curl);

        // Cleanup
        if(res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }
        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
    }
}

void handle_tcp_packet(struct ip *ip_header, const u_char *packet, std::string src_ip, std::string dst_ip, std::time_t current_time) {
    struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl * 4));

    if (tcp_header == nullptr) return;

    packets_file << "Protocol: TCP\n";
    packets_file << "Source Port: " << ntohs(tcp_header->source) << " -> Destination Port: " << ntohs(tcp_header->dest) << std::endl;
    packets_file << "Source IP: " << src_ip << " -> " << "Destination IP: " << dst_ip << "\n";

    if(tcp_header->syn && !tcp_header->ack) {
        auto &count = packet_counts[src_ip];

        if(count.syn_count == 0) {
            count.first_syn_time = std::time(nullptr);
        }
        count.syn_count++;
    }

    if(packet_counts[src_ip].syn_count > SYN_THRESHOLD && (current_time - packet_counts[src_ip].first_syn_time) < TIME_WINDOW) {
        packets_file << "Potential SYN flood detected from IP: " << src_ip << "\n";
        packets_file << "SYN Count: " << packet_counts[src_ip].syn_count << " under " << TIME_WINDOW << "s" "\n";

        send_email_alert(src_ip, packet_counts[src_ip].syn_count, tcp_header);

        packet_counts[src_ip].syn_count = 0;
        packet_counts[src_ip].first_syn_time = 0;
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14);

    std::string src_ip = inet_ntoa(ip_header->ip_src);
    std::string dst_ip = inet_ntoa(ip_header->ip_dst);
    std::time_t current_time = std::time(0);

    if (ip_header->ip_p == IPPROTO_TCP) {
        // packets_file << "Timestamp: " << ctime(&header->ts.tv_sec);

        packets_file << "Timestamp: " << std::put_time(std::localtime(&header->ts.tv_sec), "%Y-%m-%d %H:%M:%S") << std::endl;

        handle_tcp_packet(ip_header, packet, src_ip, dst_ip, current_time);

        packets_file << "Packet Length: " << header->len << " bytes\n";
        packets_file << "-------------------------------\n";
        packets_file.flush();
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 net;

    // Open the default device for live capture
    handle = pcap_open_live("wlp0s20f3", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        return 2;
    }

    // Compile and apply a filter to only capture IP packets
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        std::cerr << "Couldn't parse filter: " << pcap_geterr(handle) << std::endl;
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter: " << pcap_geterr(handle) << std::endl;
        return 2;
    }

    packets_file.open(path, std::ios::out);
    std::cout << "Opening file packets_file.txt" << std::endl;;
    if (!packets_file.is_open()) {
        std::cerr << "Error opening file packets_file.txt" << std::endl;
        return 1;
    }
    else {
        std::cout << "File packets_file.txt opened successfully" << std::endl;
    }

    // Start capturing packets and process them using the packet_handler callback
    pcap_loop(handle, PACKETS_TO_CAPTURE, packet_handler, nullptr);

    packets_file.close();

    std::cout << "File packets_file.txt closed successfully" << std::endl;

    pcap_close(handle);

    return 0;
}
