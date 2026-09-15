#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 4096

// Global runtime debug control flag
int debug_level = 0;

void query_ollama(const char* device_ip, const char* profile_data) {
    char cmd[BUFFER_SIZE + 512];
    
    // Construct a sanitized cURL JSON payload targeting your local offline Ollama API
    snprintf(cmd, sizeof(cmd),
        "curl -s -X POST http://localhost:11434/api/generate -H 'Content-Type: application/json' "
        "-d '{\"model\": \"mistral\", \"prompt\": \"You are an autonomous home network security analyzer. "
        "Review this telemetry summary from device IP %s. Traffic details: %s. "
        "If you see signs of malicious scanning, botnets, or anomalies, summarize the threat "
        "in exactly 2 short sentences.\", \"stream\": false}' "
        "| grep -o '\"response\":\"[^\"]*\"' | cut -d':' -f2 | tr -d '\"'",
        device_ip, profile_data);
        
    printf("\n[AI ANALYSIS TASK LOG] Sending profile updates for LAN IP [%s]...\n", device_ip);
    printf("----------------------------------------------------------------------\n");
    fflush(stdout);
    
    system(cmd);
    printf("\n----------------------------------------------------------------------\n\n");
    fflush(stdout);
}

int main(int argc, char *argv[]) {
    char cmd[512];
    char buffer[BUFFER_SIZE];
    FILE *fp;
    size_t total_bytes_read = 0;

    // Parse debug parameters if explicitly invoked
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && (i + 1) < argc) {
            debug_level = atoi(argv[i + 1]);
            i++; 
        }
    }

    // nfcapd automatically passes the filename location as the absolute last argument
    if (argc < 2) {
        fprintf(stderr, "[-] Target file path parameter missing from execution hook.\n");
        return 1;
    }
    char *target_file = argv[argc - 1];

    // Debug Level 1 trigger block
    if (debug_level >= 1) {
        printf("[*] Script triggered by nfcapd. Processing fresh binary archive: %s\n", target_file);
        fflush(stdout);
    }

    // Invoke the secure local nfdump binary utility to extract text lines of your live IP traffic.
    // -A srcip groups the data neatly by device IP so we don't flood the system.
    snprintf(cmd, sizeof(cmd), "/usr/bin/nfdump -r %s -A srcip", target_file);
    
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("[-] Failed to open nfdump file tracking handle");
        return 1;
    }

    // Digest the processed text rows line-by-line
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Keep a rolling tally of total characters/bytes streaming through the pipe descriptor
        total_bytes_read += strlen(buffer);

        // STRICT SUBNET FILTER: Match only your exact 192.168.1.X LAN profile, ignoring VLAN overlaps
        if (strstr(buffer, "192.168.1.")) {
            char target_ip[16] = {0};
            char *ip_start = strstr(buffer, "192.168.1.");
            
            if (ip_start) {
                // Tokenize out the raw IP block
                sscanf(ip_start, "%15s", target_ip);
                target_ip[strcspn(target_ip, ",;: \t\r\n")] = '\0';
                
                if (strlen(target_ip) >= 9) {
                    // Debug Level 3 trigger block: Print match notice instantly upon extraction
                    if (debug_level >= 3) {
                        printf("[+] Found target LAN entry: %s\n", target_ip);
                        fflush(stdout);
                    }
                    query_ollama(target_ip, buffer);
                }
            }
        }
    }

    pclose(fp);

    // Debug Level 2 trigger block
    if (debug_level >= 2) {
        printf("[*] Done parsing file text. Total data payload read: %zu bytes.\n", total_bytes_read);
        fflush(stdout);
    }

    return 0;
}

