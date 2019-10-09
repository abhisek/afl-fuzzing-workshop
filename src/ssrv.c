#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

void str_strip(char *n)
{
	char *p = n + strlen(n) - 1;
	while(p >= n) {
		if((*p != ' ') && (*p != '\n') && (*p != '\r'))
			break;

		*p-- = '\0';
	}
}

// format: type:msg
void process_msg(int sock, char *buffer)
{
  char eb[100];
  char *cmd_err = "Error - unsupported command\n";
  char *p = buffer;
  char *t = NULL;

  t = strchr(buffer, ' ');
  if(t)
    *t++ = '\0';

  if(strcmp(p, "echo") != 0) {
    send(sock, cmd_err, strlen(cmd_err), 0);
    return;
  }

  memset(eb, 0, sizeof(eb));
  sprintf(eb, "echo: %s\n", t);

  send(sock, eb, strlen(eb), 0);
}

void handle_client(int sock)
{
	char buffer[8192];

	char *prompt = "fash$ ";
	char *msg_timeout = "Your connection is being timed out.\n";

	fd_set rfds;
	struct timeval tv;

	send(sock, prompt, strlen(prompt), 0);

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

	tv.tv_sec = 10;
	tv.tv_usec = 0;

	if(select(sock + 1, &rfds, NULL, NULL, &tv) < 0)
		return;

	if(!FD_ISSET(sock, &rfds)) {
		send(sock, msg_timeout, strlen(msg_timeout), 0);
		return;
	}

	memset(buffer, 0x00, sizeof(buffer));
	if(recv(sock, buffer, sizeof(buffer) - 1, 0) > 0)
		process_msg(sock, buffer);
}

void child_handler(int signo)
{
	printf("Child exit (%d)\n", signo);
}

void segv_handler(int signo)
{
	printf("SIGSEGV (%d)\n", signo);
	exit(EXIT_FAILURE);
}

void abrt_handler(int signo)
{
	printf("SIGABRT (%d)\n", signo);
	exit(EXIT_FAILURE);
}

int srv_init()
{
	struct sockaddr_in sin;
	struct sockaddr_in cin;
	int srv_fd, cln_fd;
	int tmp;
	int sop;

	srv_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(srv_fd > 0);

	sop = 1;
	setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &sop, sizeof(sop));

	sin.sin_addr.s_addr = inet_addr("0.0.0.0");
	sin.sin_port = htons(9000);
	sin.sin_family = AF_INET;

	assert(!bind(srv_fd, (struct sockaddr*) &sin, sizeof(sin)));
	listen(srv_fd, 100);

	//signal(SIGCHLD, child_handler);
	signal(SIGCHLD, SIG_IGN);

	while(1) {
		tmp = sizeof(cin);
		cln_fd = accept(srv_fd, (struct sockaddr*) &cin, &tmp);
		if(cln_fd < 0)
			continue;

		printf("Received client from %s:%d\n", (char*) inet_ntoa(cin.sin_addr), ntohs(cin.sin_port));
		if(!fork()) {
			printf("Processing client: pid: %d socket: %d\n", getpid(), cln_fd);

			//signal(SIGSEGV, segv_handler);
			//signal(SIGABRT, abrt_handler);
			
			close(srv_fd);
			handle_client(cln_fd);

			shutdown(cln_fd, SHUT_RDWR);
			close(cln_fd);

			exit(0);
		}

		close(cln_fd);
	}
}

int main(int argc, char **argv)
{
	return srv_init();
}
