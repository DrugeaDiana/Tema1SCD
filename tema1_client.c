#include "tema1.h"
#include <stdio.h>
#include <time.h>
#include <rpc/rpc.h>
#include "token.h"

#define REQUEST "REQUEST"

// Struct used to save data about the client
// id -> client id
// auth_token -> authorization token
// access_token -> access token
// refresh_token -> refresh token
typedef struct{
	char *id;
	char *auth_token;
	char *access_token;
	char *refresh_token;
} client;

// Function to do a request to the server for authorization + access
int request_action(client *current_user, int refresh, CLIENT *handle)
{
	req_authorization_return *auth;
	req_access_param *access;
	req_access_return *access_return;
	req_access_refresh_return *access_refresh;
	approve_req_token_return *approve;

	// Request authorization
	auth = req_auth_1(&current_user->id, handle);
	if (!auth) {
		perror("");
		return -3;
	}

	// If valid == -1, the user was not found in the server database
	if (auth->valid == -1) {
		printf("USER_NOT_FOUND\n");
		return -1;
	}

	// If approved == 0, the request was denied
	current_user->auth_token = auth->auth_token;
	if (auth->approved == 0) {
		printf("REQUEST_DENIED\n");
		return -2;
	}

	// Request access
	access = malloc(sizeof(req_access_param));
	access->id = current_user->id;
	access->auth_token = current_user->auth_token;

	// Check if we have to refresh the access token or not
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
	return 1; // the request action was successful
}

// Function to validate the operation the client wants to do on a resource
void validate_action(client *current_user, char *resource, char *operation,
					 CLIENT *handle, int modified)
{
	action_param *action;
	validate_action_return *response;

	// Creates the variable that's sent as parameter to the server
	action = malloc(sizeof(action_param));
	action->operation_type = operation;
	action->resource = resource;
	// Check if it's a newly created client -> thus it would not have
	// requested access yet and not have a token
	if (modified == 0) {
		action->access_token = "NOT_FOUND";
	} else {
		action->access_token = current_user->access_token;
	}
	action->id = current_user->id;

	// Sends the request to the server to validate the action
	response = validate_action_1(action, handle);
	if (!response) {
		perror("");
		return;
	}
	printf("%s\n", response->result);

	// If the server has refreshed the tokens during the action, we update
	// them client-side as well
	if (strcmp(response->acces_token, current_user->access_token) != 0) {
		current_user->access_token = response->acces_token;
		current_user->refresh_token = response->refresh_token;
	}
	free(action);
}

// Function to parse the action from the input file
void parse_action(char *action, client ***clients, int *nr_clients,
				  CLIENT *handle)
{
	client *current_user;
	char *token = strtok(action, ",");
	// Flag to check if we have a new user (client side) or one that already
	// exists
	int modified = 0;

	if (token) {
		// Goes through the list of clients to see if the client already exists
		for (int i = 0; i < *nr_clients; i++) {
			if (strcmp((*clients)[i]->id, token) == 0) {
				current_user = (*clients)[i];
				modified = 1;
				break;
			}
		}

		// If the client does not exist, we create a new one
		if (modified == 0) {
			current_user = malloc(sizeof(client));
			current_user->id = token;
		}

		// Now we cut the string to see what the client wants to do
		token = strtok(NULL, ",");
		if (token) {
			if (strcmp(REQUEST, token) == 0) { // Request action
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
				// Wants to do an operation on a resource
				char *resource = strtok(NULL, ",\n");
				validate_action(current_user, resource, token, handle,
								modified);
			}
		}
	}
}

int main(int argc, char *argv[])
{
	/* client variable */
	CLIENT *handle;
	char *RMACHINE = argv[1];
	handle = clnt_create(RMACHINE, TEMA1PROG, TEMA1VERS, "tcp");
	if (!handle) {
		perror("");
		return -1;
	}

	// We first initialize all the variables we need
	FILE *fin = fopen(argv[2], "r");
	client **clients = malloc(100 * sizeof(client *));
	int nr_clients = 0;
	char *action;

	// We're going through the input file to parse the actions
	while (!feof(fin)) {
		// In case we need to reallocate memory for the clients
		if (nr_clients % 100 == 0) {
			clients = realloc(clients, (nr_clients + 100) * sizeof(client *));
		}
		action = malloc(100 * sizeof(char));
		fgets(action, 100, fin);
		parse_action(action, &clients, &nr_clients, handle);
	}
	fclose(fin);
	clnt_destroy(handle);

	// Free up memory
	for (int i = 0; i < nr_clients; i++) {
		free(clients[i]->id);
		free(clients[i]->access_token);
		free(clients[i]->auth_token);
		free(clients[i]);
	}
	free(clients);
	return 0;
}
