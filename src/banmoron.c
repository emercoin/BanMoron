#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <fcntl.h>

/*------------------------------------------------------------------------------*/
// 404 CGI program for perform strike-back action.
// Currently available:
//  - ban by IP (FreeBSD pf)
//  - send back zip-bomb
//  - just print the page "404 not found"
//
// Activate with apache 404 handler config line:
// ErrorDocument 404 "/cgi-bin/banmoron.cgi"
//
// Author: Oleg Khovayko (olegarch)
// License: BSD

typedef void (*action_t)(void);

struct rule {
  char		str[14];	// Substring in REQUEST_URI
  unsigned char	len;		// Actual substring lenght
  unsigned char	op_num;		// Action number (weapon)
};
struct rule g_none_rule = { "<NONE>", sizeof("<NONE>") - 1, -1 };
struct rule *g_cur_rule = &g_none_rule;

typedef enum {
  Ban      = 1,
  ZipBomb  = 2,
  Redirect = 3,
  ZipRedir = 5
} Do;

#define USE_TEST	0

// Do not ban computerd from LAN, we debug with them
#define LAN_PREFIX "192.168."
#define LOG_FNAME  "/var/log/httpd/banmoron.log"
// Hashtable mask
#define HMASK ((1 << 9) - 1)

#define BANRULE(str, op) {str, sizeof(str) - 1, op},
/*------------------------------------------------------------------------------*/

const char *g_uri, *g_ip;
int g_action_no = 0; // Default: print err404

const char htmlHead[] = 
	"Content-Type: text/html; charset=ISO-8859-1\n\n"
	"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
	"<html><head><title>404 Not Found</title></head><body>\n"
	;

/*------------------------------------------------------------------------------*/
// Just Err404 print - no any counter-action
void print_404(void) {
 const char *print_ip = (g_ip == NULL)? "tty" : g_ip;
  printf(
	"%s<h1>Page Not Found</h1>\n"
	"<p>The requested URL [%s] was not found on this server.</p>\n"
	"<p>Your IP is: [%s]</p>\n"
	"</body></html>\n", htmlHead, g_uri, print_ip);
} // print_404

/*------------------------------------------------------------------------------*/
// FreeBSD PF specified banner. Put moron's IP to pf-table "morons"
// Release will be from crontab
void ban_moron_pf(void) {
    if(g_ip == NULL) {
        printf("TTY call is not blocked\n");
        return;
    }
    if(strncmp(g_ip, LAN_PREFIX, sizeof(LAN_PREFIX) - 1) == 0) { // Preserve block LAN
        printf("%sLAN IP is not blocked: %s\n</body></html>\n", htmlHead, g_ip);
        return;
    }
    fclose(stdout);
# if defined LOG_FNAME
    int log_fd = open(LOG_FNAME, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if(log_fd >= 0) {
        char *buf = (char*)alloca(1024 + 128 + (uint8_t)rand());
        time_t now = time(NULL);
        struct tm *local = localtime(&now);
        strftime(buf, 128, "%Y-%m-%d %H:%M:%S %Z", local);
        snprintf(strchr(buf, 0), 1020, ": Block ip=[%s] in host=[%s] by rule=[%s] op=%u\n", g_ip, getenv("HTTP_HOST"), g_cur_rule->str, g_action_no);
        write(log_fd, buf, strlen(buf));
        close(log_fd);
    }
#endif
    char *parmList[] = {"/sbin/pfctl", "-qt", "morons", "-T", "add", NULL, NULL};
    parmList[5] = (char *)g_ip;
    execv(parmList[0], parmList);
} // ban_moron_pf

/*------------------------------------------------------------------------------*/
void ban_print(void) {
    printf("%sYour IP: %s is blocked\n</body></html>\n", htmlHead, g_ip);
    ban_moron_pf();
} // ban_print

/*------------------------------------------------------------------------------*/
// Send infinity zip-bomb to hacker
// bomb contains chain of HTML tags
//   <table><tr><td>
// for overflow HTML parser on hacker's side
void zip_bomb(void) {
  const char bomb_header[] = {
    0x1f,  0x8b,  0x08,  0x08,  0xfe,  0xd4,  0x97,  0x68,  0x02,  0x03,  0x62,  0x6d,  0x62,  0x2e,  0x74,  0x78,
    0x74,  0x00,  0xed,  0xc7,  0xb1,  0x09,  0x80,  0x30,  0x10,  0x40,  0xd1,  0xde,  0x65,  0x5c,  0xe0,  0xb8,
    0x5d,  0x12,  0x12,  0x48,  0x11,  0x11,  0x24,  0x8d,  0xdb,  0x2b,  0xb8,  0x83,  0xd5,  0x2b,  0x3e,  0x9f,
    0x17,  0x63,  0x1d,  0x33,  0x63,  0xf4,  0xd2,  0x32,  0xf6,  0x6f,  0xf5,  0x6c,  0x77,  0x6e,  0xb1,  0x4a,
    0x9d,  0x3d,  0x63,  0x5d,  0x6f,  0x8d,  0x99,  0x99,  0x99,  0x99,  0x99,  0x99,  0x99,  0x99,  0x99,  0x99,
  };

  char bomb_body[1024];
  memset(bomb_body, 0x99, sizeof(bomb_body));

  puts(
      "Status: 200 OK\n"
      "Content-Type: text/html; charset=ISO-8859-1\n"
      "Content-Encoding: gzip\n"
      );

  fwrite(bomb_header, sizeof(bomb_header), 1, stdout); 

  // We need ignore signal to sucessfully add client to morons table
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, SIG_IGN);

  // Send infinity zip (up to 100M), until client close connection
  for(int count = 0; count < 1000000; count++)
      if(fwrite(bomb_body, sizeof(bomb_body), 1, stdout) != 1)
          break;

  ban_moron_pf();
} // zip_bomb

/*------------------------------------------------------------------------------*/
void random_redirect(void) {
    const static char protos[4][6] = {
        "https", "https", "http", "ftp"
    };
    const char net_A[16] = { 
        24, 50,     // Comcast/8
        12, 32, 99, // AT&T/8
        58, 120,    // Deutsche Telekom/8
        42,         // Vodafone/8
        24, 50,     // Comcast/8
        52, 54,     // Amazon AWS/8
        35,         // Google Cloud/8
        40, 13,     // MS Azure/8
        68          // Cox/9
    };
    printf(
        "Status: 301 Moved Permanently\n"
        "Connection: close\n"
        "Location: "
    );

    uint32_t rnd_ip   = rand();
    uint32_t rns_port = rand();
    if((rnd_ip ^ rns_port) <= 0x00ffffff)
        // 1 ticket of 256 wins bonus - 100G file!
        printf("http://speedtest.tele2.net/100GB.zip\n\n"); 
    else
        printf("%s://%u.%u.%u.%u:%u/%x\n\n", 
           protos[(uint8_t)rnd_ip >> 6],
           net_A[rnd_ip & 0xf],
           (uint8_t)(rnd_ip >> 8),
           (uint8_t)(rnd_ip >> 16),
           (uint8_t)(rnd_ip >> 24),
           (rns_port >> 16),
           (uint16_t)(rns_port)
        );
  ban_moron_pf();
}

/*------------------------------------------------------------------------------*/
// Arsenal of weapons
//                                   0          1        2                 3
const action_t arsenal[] = { print_404, ban_print, zip_bomb, random_redirect };

// Substring length: min=3, max=13
struct rule rules[] = {
  //-------xxxXXXXXXXXXX---
  BANRULE("http://",      Ban)	// Ban - proxy scanner
  BANRULE("https://",     Ban)	// Ban - proxy scanner
  BANRULE("ftp://",       Ban)	// Ban - proxy scanner
  BANRULE("wallet",	      ZipRedir)	// Send zip-bomb to wallet lovers
  BANRULE(".bak",         ZipRedir)	// Zip+Ban - Backup lover - take backup!
  BANRULE("etc/passwd",   ZipRedir)	// Zip+Ban - passwd files lover
  BANRULE("Unblock.cgi",  ZipRedir)  // Zip+Ban - Attempt hack into router
  BANRULE(".well-known",  ZipRedir)  // Zip+Ban - Attempt download Letsencrypt
  BANRULE("../..",        ZipRedir)	// Want file? Take it!
  BANRULE("/bin/sh",      ZipRedir)	// Want shell? Get output!
  BANRULE("|sh",          ZipRedir)	// Want shell? Get output!
  BANRULE(";sh",          ZipRedir)	// Want shell? Get output!
  BANRULE("&sh",          ZipRedir)	// Want shell? Get output!
  BANRULE("curl",	      ZipRedir)	// 
  BANRULE("tftp",	      ZipRedir)	// 
  BANRULE("wget",	      ZipRedir)	// 
  BANRULE(".php",	      ZipRedir)	// 
  BANRULE("wp-content",   ZipRedir)	// 
  BANRULE("admin",        ZipRedir)	// 
  BANRULE("sdk",          ZipRedir)	// 
  BANRULE("config",       ZipRedir)	// 
  BANRULE(".zip",         ZipRedir)	// 
  BANRULE(".tgz",         ZipRedir)	// 
  BANRULE("/.git",        ZipRedir)	// 
  BANRULE("/.env",        ZipRedir)	// 
  BANRULE("/evox/",       ZipRedir)	// 
  BANRULE("ogin",         ZipRedir)	// Login/login
  BANRULE("/manager/html",ZipRedir)  // Tomcat manager
  BANRULE("/jmx-console", ZipRedir)  // JBoss
  BANRULE("/solr/",       ZipRedir)  // Apache Solr
  BANRULE("/hudson/",     ZipRedir)  // 
  BANRULE("/jenkins/",    ZipRedir)  // Jenkins
  BANRULE("busybox",      ZipRedir)  //
  BANRULE("chmod",        ZipRedir)  //
  BANRULE("/hello.world", ZipRedir)  //
  BANRULE("device.rsp",   ZipRedir)  //
  BANRULE("/mgmt.cgi",    ZipRedir)  // MikroTik & other
  BANRULE("-bin/luci",    ZipRedir)  // OpenWrt/LEDE LuCI 
  BANRULE("nmaplowerche", Redirect)	// *
  BANRULE("test-cgi",     Redirect)	// *
  //-------xxxXXXXXXXXXX---
};

#define RULES_QTY (sizeof(rules) / sizeof(struct rule))

/*------------------------------------------------------------------------------*/
int main(int argc, char **argv) {
    g_uri = getenv("REQUEST_URI");
    if((g_uri == NULL || *g_uri == 0) && argc > 1) {
        // started from command line - check rules action, no real action calls
        g_uri = argv[1];
    }
    if(g_uri == NULL || *g_uri == 0) {
        print_404();
        return 1; // Nothing to do
    }

    srand(time(NULL) ^ getpid() + clock());
    // Get some random for universal hashing & SHO
    uint32_t rnd = rand();

    g_ip  = getenv("REMOTE_ADDR");
    if(g_ip == NULL || *g_ip == 0)
        g_ip = NULL; // test IP, terminal call
    else {
        // Cleanup ip_addr with double conversion
         char *new_ip = (char *)alloca(INET6_ADDRSTRLEN + (rnd >> 24));
         const char *ret_ip = NULL;
         struct sockaddr_storage ss;
         if (inet_pton(AF_INET, g_ip, &ss) == 1)
             ret_ip = inet_ntop(AF_INET, &ss, new_ip, INET6_ADDRSTRLEN);
         else 
         if(inet_pton(AF_INET6, g_ip, &ss) == 1)
             ret_ip = inet_ntop(AF_INET6, &ss, new_ip, INET6_ADDRSTRLEN);
         else
             return 13; // Hack attempt 1 !!!
         if(ret_ip == NULL)
             return 14; // Hack attempt 2 !!!
         g_ip = new_ip;
    }

    static char htable[HMASK + 1]; // Hashtable for Rabin-Karp search algorithm

    // Fill hashtable from rules
    for(int r = 0; r < RULES_QTY; r++) {
      const char *s = rules[r].str;
      htable[(((s[0] ^ rnd) << 6) + ((s[1] ^ rnd) << 3) + (s[2] ^ rnd)) & HMASK] |= 1 << (~r & 7);
    }

    // Search for substrings using Rabin-Karp algorithm with 3-chars sliding window
    int hash = 0;
    signed char h2;
    for(const char *p = g_uri; *p; p++)
        if((h2 = htable[hash = ((hash << 3) + (*p ^ rnd)) & HMASK]) && p - g_uri >= 2) {
            int start = 0;
            do {
                if(h2 < 0)
                    for(int r = start; r < RULES_QTY; r += 8) 
                        if(strncmp(p - 2, rules[r].str, rules[r].len) == 0) {
                            g_action_no = rules[r].op_num;
                            g_cur_rule = &rules[r];
                            goto action;
                        }
                start++;
            } while(h2 <<= 1);
        } // for+if

action:
#if USE_TEST
    printf("Debug action=%d\n", g_action_no);
    return g_action_no;
#else
    if(g_action_no == ZipRedir) {
        const char *ae = getenv("HTTP_ACCEPT_ENCODING");
        g_action_no = (ae != NULL && strcasestr(ae, "gzip"))? 
            ZipBomb : Redirect;
    }
    arsenal[g_action_no](); // Use weapon from the arsenal
#endif
    return 0;
} // main

/*------------------------------------------------------------------------------*/
