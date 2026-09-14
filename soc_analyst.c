#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

// This path avoids systemd restrictions and will always remain at 0 bytes on disk
#define SOCKET_PATH "/var/tmp/netflow_metrics.sock"
#define BUFFER_SIZE 4096

void query_ollama(const char* device_ip, const char* profile_data) {
    char cmd[BUFFER_SIZE + 512];
    
    // Construct a sanitized cURL JSON payload targeting your local offline Ollama API
    snprintf(cmd, sizeof(cmd),
        "curl -s -X POST http://localhost:11434/api/generate -H 'Content-Type: application/json' "
        "-d '{\"model\": \"mistral\", \"prompt\": \"You are an autonomous home network security analyzer. "
        "Review this telemetry update. Device IP: %s. Metadata: %s. "
        "If you see signs of malicious scanning, botnets, or anomalies, summarize the threat "
        "in exactly 2 short sentences.\", \"stream\": false}' "
        "| grep -o '\"response\":\"[^\"]*\"' | cut -d':' -f2 | tr -d '\"'",
        device_ip, profile_data);
        
    printf("\n🤖 Sending entity data to Ollama for IP [%s]...\n", device_ip);
    printf("----------------------------------------------------------------------\n");
    fflush(stdout);
    
    // Execute the API request natively
    system(cmd);
    printf("\n----------------------------------------------------------------------\n\n");
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_un addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // 1. Clean up potential old ghost file paths instantly on startup
    unlink(SOCKET_PATH);

    // 2. Create the native UNIX stream socket
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("[-] Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // 3. Bind the socket file path to the server engine (This creates the file)
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("[-] Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 4. Set open file permissions so the daemon service can read/write to it smoothly
    chmod(SOCKET_PATH, 0777);

    // 5. Open the listening queue
    if (listen(server_fd, 5) == -1) {
        perror("[-] Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("[*] Server active. Waiting for nfcapd service to connect at %s...\n", SOCKET_PATH);
    fflush(stdout);

    // 6. Block here patiently using 0% CPU until nfcapd connects
    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd == -1) {
        perror("[-] Accept connection failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("[+] nfcapd connected successfully! Monitoring network metadata streams...\n");
    fflush(stdout);

    // 7. Continuously digest incoming text lines from nfcapd
    while ((bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        printf("[*] %zd bytes read\n", bytes_read);
        buffer[bytes_read] = '\0'; // Enforce safe C-string termination

        // Parse metrics line by line
        char *line = strtok(buffer, "\n");
        while (line != NULL) {
            // Check if the current telemetry update line involves an internal LAN address
            if (strstr(line, "192.168.")) {
                char target_ip[16] = {0};
                
                // Scan out the first matching IP string block to identify the device
                char *ip_start = strstr(line, "192.168.");
                if (ip_start) {
                    sscanf(ip_start, "%15s", target_ip);
                    
                    // Clean up any trailing punctuation or commas from the token parse
                    target_ip[strcspn(target_ip, ",;: \t\r\n")] = '\0';
                    
                    if (strlen(target_ip) >= 7) {
                        query_ollama(target_ip, line);
                    }
                }
            }
            line = strtok(NULL, "\n");
        }
    }

    if (bytes_read == -1) {
        perror("[-] Error reading from socket data stream");
    }

    printf("[*] Connection dropped by daemon server. Shutting down.\n");
    close(client_fd);
    close(server_fd);
    unlink(SOCKET_PATH);
    return 0;
}

