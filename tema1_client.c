
#include "tema1.h"
#include <stdio.h> 
#include <time.h> 
#include <rpc/rpc.h>
#include "token.h"
#define REQUEST "REQUEST"

typedef struct{
	char *id;
	char *auth_token;
	char *access_token;
} client ;

int request_action(client *current_user, int refresh, CLIENT *handle) {
	req_authorization_return *auth;
	req_access_param *access;
	req_access_return *access_return;
	approve_req_token_return *approve;

	auth = req_auth_1(&current_user->id, handle);
	if (auth == NULL) {
		perror("");
		return;
	}
	if (auth->valid == -1) {
		printf("USER_NOT_FOUND\n");
		return -1;
	}
	current_user->auth_token = auth->auth_token;
	if (auth->approved == 0) {
		printf("REQUEST_DENIED\n");
		return -2;
	}
	access = malloc(sizeof(req_access_param));
	access->id = current_user->id;
	access->auth_token = current_user->auth_token;
	access_return = req_access_1(access, handle);
	if (access_return == NULL) {
		perror("");
		return;
	}
	current_user->access_token = access_return->access_token;
	free(access);

	printf("%s -> %s\n", current_user->id, current_user->access_token);
	return 1;
}

void parse_action(char *action, client ***clients, int *nr_clients, CLIENT *handle) {
	client *current_user;
	char *token = strtok(action, ",");
	int modified = 0;
	if (token != NULL) {
		for (int i = 0; i < *nr_clients; i++) {
			if (strcmp((*clients)[i]->id, token) == 0) {
				current_user = (*clients)[i];
				modified = 1;
				break;
			}
		}
		if (modified == 0) {
			current_user = malloc(sizeof(client));
			current_user->id = token;
		}
		token = strtok(NULL, ",");
		if (token != NULL) {
			if (strcmp(REQUEST, token) == 0) {
				int refresh = atoi(strtok(NULL, ","));
				if (token != NULL) {
					int ret = request_action(current_user, refresh, handle);
					if (ret == -1 || ret == -2) {
						free(current_user);
						free(action);
						return;
					} else if (modified == 0) {
						(*clients)[*nr_clients] = current_user;
						(*nr_clients)++;
					} else {
						free(action);
					}
				} else {
					printf("Invalid request\n");
				}
			} else {
				char *resource = strtok(NULL, ",");
				printf("Actiune neimplementata inca\n");
			}
		}
	}
}

int main(int argc, char *argv[]){

	/* variabila clientului */
	CLIENT *handle;
	char *RMACHINE = argv[1];

	handle=clnt_create(
		RMACHINE,		/* numele masinii unde se afla server-ul */
		TEMA1PROG,		/* numele programului disponibil pe server */
		TEMA1VERS,		/* versiunea programului */
		"tcp");			/* tipul conexiunii client-server */
	
	if(handle == NULL) {
		perror("");
		return -1;
	}

	FILE *fin = fopen(argv[2], "r");
	client **clients = malloc(100 * sizeof(client*));
	int nr_clients = 0;
	char* action;
	while (!feof(fin)) {
		action = malloc(100 * sizeof(char));
		fgets(action, 100, fin);
		parse_action(action, &clients, &nr_clients, handle);
	}

	fclose(fin);
	clnt_destroy(handle);
	for (int i = 0; i < nr_clients; i++) {
		free(clients[i]->id);
		free(clients[i]->access_token);
		free(clients[i]->auth_token);
		free(clients[i]);
	}
	free(clients);
	return 0;
}
