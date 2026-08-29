/* Retrying client: connect/sendto, retry on EAGAIN, print the settled errno. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	if (argc != 4) { fprintf(stderr, "usage: %s tcp|udp ip port\n", argv[0]); return 2; }
	int udp = strcmp(argv[1], "udp") == 0;
	struct sockaddr_in d;
	memset(&d, 0, sizeof(d));
	d.sin_family = AF_INET;
	d.sin_port = htons(atoi(argv[3]));
	inet_pton(AF_INET, argv[2], &d.sin_addr);

	for (int i = 0; i < 400; i++) {
		int s = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
		int r = udp ? sendto(s, "x", 1, 0, (struct sockaddr *)&d, sizeof(d))
			    : connect(s, (struct sockaddr *)&d, sizeof(d));
		int e = (r < 0) ? errno : 0;
		close(s);
		if (e != EAGAIN) {
			printf("%s %s:%s -> %s (after %d retr%s)\n", argv[1], argv[2], argv[3],
			    e ? strerror(e) : "ok", i, i == 1 ? "y" : "ies");
			return 0;
		}
		usleep(5000);
	}
	printf("%s %s:%s -> still EAGAIN (never resolved)\n", argv[1], argv[2], argv[3]);
	return 1;
}
