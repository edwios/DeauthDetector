// This software is licensed under the MIT License.
// See the license file for details.
// For more details visit github.com/spacehuhn/DeauthDetector

// include necessary libraries
#include <ESP8266WiFi.h>
#include "SH1106.h" alis for `#include "SH1106Wire.h"`

// include ESP8266 Non-OS SDK functions
extern "C" {
#include "user_interface.h"
}

SH1106 display(0x3c, 4, 5);

// ===== SETTINGS ===== //
#define BUZZER 14
#define LED 2              /* LED pin (2=built-in LED) */
#define LED_INVERT true    /* Invert HIGH/LOW for LED */
#define SERIAL_BAUD 115200 /* Baudrate for serial communication */
#define CH_TIME 140        /* Scan time (in ms) per channel */
#define PKT_RATE 5         /* Min. packets before it gets recognized as an attack */
#define PKT_TIME 1         /* Min. interval (CH_TIME*CH_RANGE) before it gets recognized as an attack */

// Channels to scan on (US=1-11, EU=1-13, JAP=1-14)
const short channels[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13/*,14*/ };

// ===== Runtime variables ===== //
int ch_index { 0 };               // Current index of channel array
unsigned int packet_rate { 0 };            // Deauth packet counter (resets with each update)
unsigned int attack_counter { 0 };         // Attack counter
unsigned long update_time { 0 };  // Last update time
unsigned long ch_time { 0 };      // Last channel hop time
unsigned short ch;
unsigned short attack_ch = 99;
unsigned int attack_rate = 0;
unsigned long start_time;
float attack_time = 0.0f;

String bssid;
String staid;
String sta2id;
char chid[10];
String mac_1;
String mac_2;
String mac_3;
String attack_mac_1 = "ff:ff:ff:ff:ff:ff";
String attack_mac_2 = "ff:ff:ff:ff:ff:ff";
String attack_mac_3 = "ff:ff:ff:ff:ff:ff";

// ===== Sniffer function ===== //
void sniffer(uint8_t *buf, uint16_t len) {
  if (!buf || len < 28) return; // Drop packets without MAC header

  // Byte 0-11 belongs to RxControl
  byte pkt_type = buf[12]; // second half of frame control (byte 12,13) field
  mac_1 = macToString((char *)&buf[16]);
  mac_2 = macToString((char *)&buf[22]);
  mac_3 = macToString((char *)&buf[28]);

  // If captured packet is a deauthentication or dissassociaten frame
  if (pkt_type == 0xA0 || pkt_type == 0xC0) {
    ++packet_rate;
  }
}

String macToString(char* mac) {
  char buf[20];
  snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

char * macToChars(char* mac) {
  char buf[20];
  snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return (char *)buf;
}

// ===== Attack detection functions ===== //
void attack_started() {
  String ssid;
  
  digitalWrite(LED, !LED_INVERT); // turn LED on
  digitalWrite(BUZZER, !LED_INVERT); // turn BUZZER on
  attack_mac_1 = mac_1;
  attack_mac_2 = mac_2;
  attack_mac_3 = mac_3;
  attack_ch = ch;
  attack_rate = packet_rate;
  Serial.println("ATTACK DETECTED");
}

void attack_stopped() {
  digitalWrite(LED, LED_INVERT); // turn LED off
  digitalWrite(BUZZER, LED_INVERT); // turn BUZZER off
  Serial.println("ATTACK STOPPED");
}

// ===== Setup ===== //
void setup() {
  Serial.begin(SERIAL_BAUD); // Start serial communication

  pinMode(LED, OUTPUT); // Enable LED pin
  pinMode(BUZZER, OUTPUT); // Enable buzzer pin
  digitalWrite(LED, LED_INVERT);
  digitalWrite(BUZZER, LED_INVERT);

  // Initialising the UI will init the display too.
  display.init();
  display.flipScreenVertically();
  display.setFont(ArialMT_Plain_10);
  display.clear();

  // text display tests
  display.setTextAlignment(TEXT_ALIGN_LEFT);
  display.setFont(ArialMT_Plain_10);
  display.drawString(0, 0, "Initializing Wi-Fi");
  display.display();
  
  WiFi.disconnect();                   // Disconnect from any saved or active WiFi connections
  wifi_set_opmode(STATION_MODE);       // Set device to client/station mode
  wifi_set_promiscuous_rx_cb(sniffer); // Set sniffer function
  wifi_set_channel(channels[0]);        // Set channel
  wifi_promiscuous_enable(true);       // Enable sniffer

  Serial.println("Started \\o/");
  display.drawString(0, 10, "Ready!!");
  display.display();
  delay(500);
  display.clear();
  display.drawString(24, 0, "Deauth detector");
  display.drawLine(0,12,127,12);
  display.display();
}

// ===== Loop ===== //
void loop() {
  unsigned long current_time = millis(); // Get current time (in ms)
  
  // Update each second (or scan-time-per-channel * channel-range)
  if (current_time - update_time >= (sizeof(channels)*CH_TIME)) {
    update_time = current_time; // Update time variable

    // When detected deauth packets exceed the minimum allowed number
    if (packet_rate >= PKT_RATE) {
      ++attack_counter; // Increment attack counter
    } else {
      if(attack_counter >= PKT_TIME) {
        attack_stopped();
        attack_time = (current_time - start_time)/1000.0f;
      }
      attack_counter = 0; // Reset attack counter
    }

    // When attack exceeds minimum allowed time
    if (attack_counter == PKT_TIME) {
      attack_started();
      start_time = current_time;
    }
    
    Serial.print("Packets/s: ");
    Serial.println(packet_rate);
    bssid = "Dst: " + attack_mac_1;
    staid = "Src: " + attack_mac_2;
    sta2id = "Bss: " + attack_mac_3;
    snprintf(chid, 9, "  CH: %2d", attack_ch);

    display.setColor(BLACK);
    display.fillRect(0, 13, 127,63);
    display.setColor(WHITE);
    display.drawString(0, 16, "Rate: " + String(attack_rate) + String(chid) + " T: " + String(attack_time, 1) + "s");
    display.drawString(0, 30, bssid);
    display.drawString(0, 40, staid);
    display.drawString(0, 50, sta2id);

    packet_rate = 0; // Reset packet rate
  }

  // Channel hopping
  if (sizeof(channels) > 1 && current_time - ch_time >= CH_TIME) {
    ch_time = current_time; // Update time variable

    // Get next channel
    ch_index = (ch_index+1) % (sizeof(channels)/sizeof(channels[0]));
    ch = channels[ch_index];

    // Set channel
    //Serial.print("Set channel to ");
    //Serial.println(ch);
    wifi_set_channel(ch);
  }
  display.display();

}
