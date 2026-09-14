#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#define SOCKET_PATH "/var/tmp/netflow_metrics.sock"
#define BUFFER_SIZE 4096

// Global runtime flags
int debug_level = 0;

void query_ollama(const char* device_ip, const char* profile_data) {
    char cmd[BUFFER_SIZE + 512];
    
    snprintf(cmd, sizeof(cmd),
        "curl -s -X POST http://localhost:11434/api/generate -H 'Content-Type: application/json' "
        "-d '{\"model\": \"mistral\", \"prompt\": \"You are an autonomous home network security analyzer. "
        "Review this telemetry update. Device IP: %s. Metadata: %s. "
        "If you see signs of malicious scanning, botnets, or anomalies, summarize the threat "
        "in exactly 2 short sentences.\", \"stream\": false}' "
        "| grep -o '\"response\":\"[^\"]*\"' | cut -d':' -f2 | tr -d '\"'",
        device_ip, profile_data);
        
    printf("\n Sending entity data to Ollama for IP [%s]...\n", device_ip);
    printf("----------------------------------------------------------------------\n");
    fflush(stdout);
    
    system(cmd);
    printf("\n----------------------------------------------------------------------\n\n");
}

int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_un addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // Parse runtime arguments for debug control
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && (i + 1) < argc) {
            debug_level = atoi(argv[i + 1]);
            i++; // Skip the value token
        }
    }

    unlink(SOCKET_PATH);

    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("[-] Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("[-] Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    chmod(SOCKET_PATH, 0777);

    if (listen(server_fd, 5) == -1) {
        perror("[-] Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("[*] Server active. Listening for connections at %s... (Debug Level: %d)\n", SOCKET_PATH, debug_level);
    fflush(stdout);

    // Continuous server loop to handle periodic disconnects without terminating the service
    while (1) {
        if (debug_level >= 1) {
            printf("[*] Waiting for nfcapd handshake...\n");
            fflush(stdout);
        }
        
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1) {
            perror("[-] Accept connection failed");
            continue; 
        }

        if (debug_level >= 1) {
            printf("[+] nfcapd connected successfully! Monitoring network metadata streams...\n");
            fflush(stdout);
        }

        while ((bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytes_read] = '\0'; 

            // Conditional print statement driven by your runtime argument config
            if (debug_level >= 1) {
                printf("[*] %zd bytes read\n", bytes_read);
                fflush(stdout);
            }

            char *line = strtok(buffer, "\n");
            while (line != NULL) {
                if (strstr(line, "192.168.")) {
                    char target_ip[16] = {0};
                    char *ip_start = strstr(line, "192.168.");
                    if (ip_start) {
                        sscanf(ip_start, "%15s", target_ip);
                        target_ip[strcspn(target_ip, ",;: \t\r\n")] = '\0';
                        if (strlen(target_ip) >= 7) {
                            query_ollama(target_ip, line);
                        }
                    }
                }
                line = strtok(NULL, "\n");
            }
        }

        if (debug_level >= 1) {
            printf("[*] Connection closed by daemon server. Returning to standby.\n");
            fflush(stdout);
        }
        close(client_fd); 
    }

    close(server_fd);
    unlink(SOCKET_PATH);
    return 0;
}

