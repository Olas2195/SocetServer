#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#include <iostream>
#include <string>
#include "base64.c"
#include "sha1.c"
#include <fstream>
#include <sstream>

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

void wifi_ws_generate_ssh1(char* source, char* generated)
{
    //Generuje odpowiedź da klucza wysłanego przez klienta websocket na HANDSHAKE (pierwszy GET)
    //UWAGA! Musi być przyznana pamięć dla generated 128
    //TODO wygenerować swoj Magic Key:
    const char* magicStringFX = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";//"7AC87B2C-9579-4E7D-8E5D-663F60E4797B";//"7ac87b2c-9579-4e7d-8e5d-663f60e4797b";
    //char *magicTest = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char shaSourceGUID[128];//"dGhlIHNhbXBsZSBub25jZQ=="; //24
    strcpy_s(shaSourceGUID, source); //pierwsza czesc stringu to kopia
    strcat_s(shaSourceGUID, magicStringFX);
    char SHA1result[32];//21
    SHA1(SHA1result, shaSourceGUID, strlen(shaSourceGUID));
    Base64encode(generated, SHA1result, strlen(SHA1result));
}

void wifi_ws_handshake_send(char* wsKey, uint8_t channel, char* handShake)
{

    char wsKeyResponse[128];
    wifi_ws_generate_ssh1(wsKey, wsKeyResponse);
    snprintf(handShake, 1023, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: lws-minimal\r\nAccess-Control-Allow-Origin: *\r\n\n", wsKeyResponse);
    //"HTTP/1.1 101 Switching Protocols\nUpgrade: WebSocket\nConnection: Upgrade\nSec-WebSocket-Accept: BG/pdcLBIS/cwqVQmA3LWkinc7U=\nSec-WebSocket-Protocol: lws-minimal\n");
    signed int l = strlen(handShake);
}



int main() {

    WSADATA wsaData;

    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != NO_ERROR)
        printf("Initialization error.\n");

    //cz2
    SOCKET mainSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (mainSocket == INVALID_SOCKET)
    {
        printf("Error creating socket: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    //cz3
    sockaddr_in service;
    memset(&service, 0, sizeof(service));
    service.sin_family = AF_INET;
    //service.sin_addr.s_addr = inet_addr("127.0.0.1");
    InetPton(AF_INET, (PCWSTR)"127.0.0.1:27015", &service.sin_addr.s_addr); //adres nasłuchujący
    service.sin_port = htons(27015); //port

    if (bind(mainSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR)
    {
        printf("bind() failed.\n");
        closesocket(mainSocket);
        return 1;
    }

    if (listen(mainSocket, 1) == SOCKET_ERROR)
        printf("Error listening on socket.\n");
    SOCKET acceptSocket = SOCKET_ERROR;
    printf("Waiting for a client to connect...\n");

    while (acceptSocket == SOCKET_ERROR)
    {
        acceptSocket = accept(mainSocket, NULL, NULL);
    }

    printf("Client connected.\n");
    mainSocket = acceptSocket;


    int bytesSent;
    int bytesRecv = SOCKET_ERROR;
    char sendbuf[4048] = "Server says hello!";
    char recvbuf[4048] = "";

    bytesRecv = recv(mainSocket, recvbuf, 4048, 0);
    printf("Bytes received: %ld\n", bytesRecv);
    printf("Received text: %s\n", recvbuf);

    char handShake[1024]; //Access-Control-Allow-Origin: *
    char* websocketKey = strstr((char*)recvbuf, "Sec-WebSocket-Key: ");
    if (websocketKey)
    { //znaleziono klucz Handshake w żądaniu HTTP
        websocketKey += 19; //"Sec-WebSocket-Key: " dalej
        printf("Websocket connection! Sending HTTP handshake.\r\n");
        char* websocketKeyEnd = strchr(websocketKey, '\r');
        if (!websocketKeyEnd)
            websocketKeyEnd = strchr(websocketKey, '\n');
        if (!websocketKeyEnd)
        {
            printf("ERROR: \r or \n not found after the key!");
        }
        else
        { //znaleziono \r lun \n po kluczu handshake
            char wsKey[64];
            uint8_t wsKeyLen = websocketKeyEnd - websocketKey; //dlugosc to wskaznik konca-poczatku
            if (wsKeyLen <= 63)
            { //max dlugosc klucza hs

                memcpy(wsKey, websocketKey, wsKeyLen); //zapisz klucz do nowej zmiennej
                wsKey[wsKeyLen] = '\0'; //zakoncz string
                wifi_ws_handshake_send(wsKey, 0, handShake); //wyslij odpowiedz handshake z nowym kluczem
            }
            else
            {//za dlugi klucz w naglowku HTTP (powinno być <32 znaki ma 64 ale i to nie starczylo
                printf("ERROR: too long websocketKey: %i\r\n", wsKeyLen);
            }
        }

    }
    else
    {
        printf("Websocket key not received from client - broken HTTP header!\r\n");
    }

    //wysyłamy odpowiedź
    bytesSent = send(mainSocket, handShake, strlen(handShake), 0);
    printf("Bytes sent: %ld\n", bytesSent);

    system("pause");

    return 0;
}