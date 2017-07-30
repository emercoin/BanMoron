#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/*------------------------------------------------------------------------------*/

typedef void (*action_t)(void);

struct rule {
  char		str[11];	// Substring in REQUEST_URI
  unsigned char	op_num;		// Action number (weapon)
};

#define LAN_PREFIX "192.168."

const struct rule rules[] = {
 {".php",	1},	// Ban PHP-reader
 {"wallet",	2},	// Send zip-bomb to wallet lovers
 {"",		0}	// End of table
};

/*------------------------------------------------------------------------------*/

char *g_uri, *g_ip;

const char htmlHead[] = 
	"Content-Type: text/html; charset=ISO-8859-1\n\n"
	"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
	"<html><head><title>404 Not Found</title></head><body>\n"
	;

/*------------------------------------------------------------------------------*/
// Just Err404 print - no any counter-action
void print_404(void) {
  printf(
	"%s<h1>Page Not Found</h1>\n"
	"<p>The requested URL [%s] was not found on this server.</p>\n"
	"<p>Your IP: %s</p>\n"
	"</body></html>\n", htmlHead, g_uri, g_ip);
} // print_404

/*------------------------------------------------------------------------------*/
// Common ban function. Must be called from filter-specific weapon
// Release will be from crontab
void ban_moron(char **parmList) {
  if(strncmp(g_ip, LAN_PREFIX, sizeof(LAN_PREFIX) - 1) == 0) { // Preserve block LAN
    printf("%sLAN IP is not blocked: %s\n</body></html>\n", htmlHead, g_ip);
  } else {
    printf("%sBlocked IP: %s\n</body></html>\n", htmlHead, g_ip);
    fclose(stdout);

    // Allow only [:.0-9A-Za-z] in the IP to preserve possible REMOTE_ADDR hack
    for(char c, *p = g_ip; (c = *p) != 0; p++) {
      if(!(
	    (c >= '0' && c <= '9') ||
	     c == '.' || c == ':'  ||
	    (c >= 'a' && c <= 'f') ||
	    (c >= 'A' && c <= 'F')
	 ))
        return; // Hacked REMOTE_ADDR, unable to block
    } // for
    execv(parmList[0], parmList);
  } // else -- LAN
} // block_moron_pf

/*------------------------------------------------------------------------------*/
// FreeBSD PF specified banner. Put moron's IP to pf-table "morons"
// Release will be from crontab
void ban_moron_pf(void) {
  char *parmList[] = {"/sbin/pfctl", "-qt", "morons", "-T", "add", NULL, NULL};
  parmList[5] = g_ip;
  ban_moron(parmList);
} // block_moron_pf

/*------------------------------------------------------------------------------*/
// Send infinity zip-bomb to hacker
void zip_bomb(void) {
  const char bomb_header[] = {
    0x1f,0x8b,0x08,0x08,0x30,0x8d,0x72,0x59,0x02,0x03,0x62,0x6f,0x6d,0x62,0x2e,0x74,
    0x78,0x74,0x00,0xed,0xca,0xc1,0x09,0xc3,0x30,0x10,0x04,0xc0,0xbf,0xaa,0x48,0x07,
    0x6e,0xe0,0x50,0x2f,0x12,0x32,0xd8,0x60,0xe3,0x10,0xf4,0x89,0xab,0xb7,0x8c,0xd3,
    0x42,0x7e,0xf3,0x38,0x96,0xd9,0xbd,0x58,0xfa,0xbe,0xe5,0x14,0xcb,0x5c,0xda,0x88,
    0xbe,0xf6,0x6d,0xce,0xe7,0xfa,0x7e,0xd5,0x63,0xaf,0x31,0x3d,0x4e,0x31,0xfd,0xf6,
    0x7a,0xb4,0xef,0xfd,0x56,0xea,0xa8,0xa3,0x7f,0xc6,0x35,0x66,0x66,0x66,0x66,0x66
  };

  char bomb_body[1024];
  memset(bomb_body, 0x66, 1024);

  puts(
      "Content-Type: text/html; charset=ISO-8859-1\n"
      "Content-Encoding: gzip\n"
      );

  fwrite(bomb_header, 16, 6, stdout); // Send infinity zip, untill connection broken
  while(fwrite(bomb_body, 1024, 1, stdout) != 1);

} // block_moron_pf

/*------------------------------------------------------------------------------*/
// Send zip-bomb and ban thereafter
void zip_ban(void) {
  zip_bomb();
  ban_moron_pf();
} // zip_ban

/*------------------------------------------------------------------------------*/
// Arsenal of weapons
//				0		1	2	3
const action_t arsenal[] = { print_404, ban_moron_pf, zip_bomb, zip_ban };

/*------------------------------------------------------------------------------*/

int main(int argc, char **argv) {
  g_uri = getenv("REQUEST_URI");
  g_ip  = getenv("REMOTE_ADDR");

  if(g_ip && g_uri) {
    const struct rule *r = rules;
    while(r->str[0] != 0 && strstr(g_uri, r->str) == NULL)
      r++;
    arsenal[r->op_num](); // Use weapon from arsenal
  }

  return 0;
} // main

/*------------------------------------------------------------------------------*/
