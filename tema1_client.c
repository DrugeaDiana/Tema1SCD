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
	char *refresh_token;
} client;

int request_action(client *current_user, int refresh, CLIENT *handle)
{
	req_authorization_return *auth;
	req_access_param *access;
	req_access_return *access_return;
	req_access_refresh_return *access_refresh;
	approve_req_token_return *approve;

	auth = req_auth_1(&current_user->id, handle);
	if (!auth) {
		perror("");
		return -3;
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
	if (refresh == 0) {
		access_return = req_access_1(access, handle);
		if (!access_return) {
			perror("");
			return -3;
		}
		current_user->access_token = access_return->access_token;
		printf("%s -> %s\n", current_user->auth_token,
			   current_user->access_token);
	} else {
		access_refresh = req_access_refr_1(access, handle);
		if (!access_refresh) {
			perror("");
			return -3;
		}
		current_user->access_token = access_refresh->access_token;
		current_user->refresh_token = access_refresh->refresh_token;

		printf("%s -> %s,%s\n", current_user->auth_token,
			   current_user->access_token, current_user->refresh_token);
	}
	free(access);
	return 1;
}

void validate_action(client *current_user, char *resource, char *operation,
					 CLIENT *handle, int modified)
{
	action_param *action;
	validate_action_return *response;

	action = malloc(sizeof(action_param));
	action->operation_type = operation;
	action->resource = resource;
	if (modified == 0) {
		action->access_token = "NOT_FOUND";
	} else {
		action->access_token = current_user->access_token;
	}
	action->id = current_user->id;

	response = validate_action_1(action, handle);
	if (!response) {
		perror("");
		return;
	}
	printf("%s\n", response->result);

	if (strcmp(response->acces_token, current_user->access_token) != 0) {
		current_user->access_token = response->acces_token;
		current_user->refresh_token = response->refresh_token;
	}
	free(action);
}

void parse_action(char *action, client ***clients, int *nr_clients,
				  CLIENT *handle)
{
	client *current_user;
	char *token = strtok(action, ",");
	int modified = 0;
	if (token) {
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
		if (token) {
			if (strcmp(REQUEST, token) == 0) {
				int refresh = atoi(strtok(NULL, ",\n"));
				if (token) {
					int ret = request_action(current_user, refresh, handle);
					if (ret == -1 || ret == -2 || ret == -3) {
						free(action);
						return;
					} else if (modified == 0) {
						(*clients)[*nr_clients] = current_user;
						(*nr_clients)++;
					} else {
						free(action);
					}
				}
			} else {
				char *resource = strtok(NULL, ",\n");
				validate_action(current_user, resource, token, handle,
								modified);
			}
		}
	}
}

int main(int argc, char *argv[])
{
	/* variabila clientului */
	CLIENT *handle;
	char *RMACHINE = argv[1];
	handle = clnt_create(RMACHINE, TEMA1PROG, TEMA1VERS, "tcp");
	if (!handle) {
		perror("");
		return -1;
	}

	FILE *fin = fopen(argv[2], "r");
	client **clients = malloc(100 * sizeof(client *));
	int nr_clients = 0;
	char *action;
	while (!feof(fin)) {
		if (nr_clients % 100 == 0) {
			clients = realloc(clients, (nr_clients + 100) * sizeof(client *));
		}
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
