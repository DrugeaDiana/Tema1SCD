#include "tema1.h"
#include <stdio.h>
#include <time.h>
#include <rpc/rpc.h>
#include "token.h"

#define NOT_APROVED "*,-\n"
#define NOT_FOUND "NOT_FOUND"
#define EXECUTE "EXECUTE"

/* Struct used to save all the information about a client into the database
id -> the id of the client
auth_token -> the authorization token of the client
access_token -> the access token of the client
refresh_token -> the refresh token of the client (if it exists)
valability -> the valability of the access token (how many actions can still
be done 'till we have to renew)
approved -> if the client was aproved or not
permissions -> the permissions of the client
refresh -> if the client has a refresh token active
*/
typedef struct {
	char *id;
	char *auth_token;
	char *access_token;
	char *refresh_token;
	int valability;
	int approved;
	char *permissions;
	int refresh;
}	client;

// The vector where we save all the resources the server has
char **resources;
// The clients database
client **clients;
// The maximum valability of the access token (got from the command line)
int max_valability;
// The number of clients
int nr_clients;
// The number of resources
int nr_res;
// The counter for the requests -> to know which approval is for which request
int request_counter;
// The file from where we get the response towards the clients
char *aprob_file;

/* Function to initialize the server: it reads the clients and resources from
the corresponding files, and sets the maximum valability of the access token
*/
void init_server(int argc, char **argv)
{
	// Opening the clients file
	FILE *f_id = fopen(argv[1], "r");
	if (!f_id) {
		perror("Error opening file");
		exit(1);
	}

	// Allocating the memory needed for the clients
	char *line = malloc(20 * sizeof(char));
	fgets(line, 20, f_id);
	nr_clients = atoi(line);
	clients = malloc(nr_clients * sizeof(client *));

	// Read the clients from the file
	for (int i = 0; i < nr_clients; i++) {
		clients[i] = malloc(sizeof(client));
		fgets(line, 17, f_id);
		clients[i]->id = malloc(17 * sizeof(char));
		char *token = strtok(line, "\n");
		clients[i]->id = strdup(token);
	}
	fclose(f_id);
	free(line);

	char *res_line = malloc(100 * sizeof(char));
	FILE *f_res = fopen(argv[2], "r");
	if (!f_res) {
		perror("Error opening file");
		exit(1);
	}

	// Allocating the memory neded to read the resources
	fgets(res_line, 16, f_res);
	nr_res = atoi(res_line);
	resources = malloc(nr_res * sizeof(char *));

	// Reading the resources
	for (int i = 0; i < nr_res; i++) {
		resources[i] = malloc(100 * sizeof(char));
		fgets(res_line, 100, f_res);
		char *token = strtok(res_line, "\n");
		resources[i] = strdup(token);
	}
	fclose(f_res);
	free(res_line);

	aprob_file = argv[3]; // save what the file with the aprovals is
	max_valability = atoi(argv[4]); // save the maximum valability of the token
	request_counter = 0; // puts the request counter to 0
}

// Goes through the list of clients and finds the one with the given id
client *check_id(char *id)
{
	for (int i = 0; i < nr_clients; i++) {
		if (strcmp(clients[i]->id, id) == 0) {
			return clients[i];
		}
	}
	return NULL;
}

// Generates a new auth token based on the id of the client
req_authorization_return *
req_auth_1_svc(char **argp, struct svc_req *rqstp)
{
	static req_authorization_return  result;

	printf("BEGIN %s AUTHZ\n", *argp);
	client *client = check_id(*argp); // check if the client is in the database
	if (!client) {
		result.id = *argp;
		result.auth_token = *argp;
		result.valid = -1; // puts valid to 1 -> USER_NOT_FOUND
		return &result;
	}

	// Fills up the result with all the data needed
	result.id = *argp;
	result.auth_token = generate_access_token(*argp);
	result.valid = 1;
	client->auth_token = result.auth_token;
	printf("  RequestToken = %s\n", result.auth_token);

	// Goes into the aproval process
	approve_req_token_return *approve;
	approve = approve_token_1_svc(&result.auth_token, rqstp);

	// Checks if the request was approved or not
	if (approve->approved == 0) {
		result.approved = 0;
	} else {
		result.approved = 1;
	}
	client->permissions = approve->permisions;
	client->approved = result.approved;
	return &result;
}

// Generates a new access token based on the auth token of the client
req_access_return *
req_access_1_svc(req_access_param *argp, struct svc_req *rqstp)
{
	static req_access_return  result;
	// Gets the client with the specific id
	// It will always be in the database as we already checked it in the
	// request authorization function
	client *client = check_id(argp->id);

	// Fills up the result variable with all the data needed
	result.id = argp->id;
	result.auth_token = argp->auth_token;
	result.access_token = generate_access_token(argp->auth_token);

	// Fills up the client variable with all the data generated
	client->access_token = result.access_token;
	client->valability = max_valability;
	client->refresh = 0; // Puts the refresh to 0 since we don't have a refresh

	printf("  AccessToken = %s\n", result.access_token);
	fflush(NULL);
	return &result;
}

// Checks to see if the resource we want to access is in the database
int check_resource(char *resource)
{
	for (int i = 0; i < nr_res; i++) {
		if (strcmp(resources[i], resource) == 0) {
			return 1;
		}
	}
	return 0;
}

// Struct used to save the new access and refresh tokens that get regenerated
typedef struct {
	char *refresh;
	char *access;
} refresh_change;

// Generates a new access and refresh token for when the access token expires
refresh_change refresh(char *refresh_token, char *id)
{
	refresh_change result;
	result.access = generate_access_token(refresh_token);
	result.refresh = generate_access_token(result.access);

	printf("BEGIN %s AUTHZ REFRESH\n", id);
	printf("  AccessToken = %s\n", result.access);
	printf("  RefreshToken = %s\n", result.refresh);
	fflush(NULL);
	return result;
}

// Checks to see if the client has the permission to execute a certain operation
// on a certain resource
int check_permision(char *operation, char *permissions, char *resource)
{
	// We cut the permission string into tokens, based on where the ',' is
	char *token = strtok(permissions, ",");
	while (token) {
		if (strcmp(token, resource) == 0) {
			token = strtok(NULL, ","); // get the operations permited
			for (int i = 0; i < strlen(token); i++) {
				// Because of how the operations are saved in the file,
				// the permited operations will either be the first letter of
				// what the client wants to do, or the second letter if it's
				// "EXECUTE" operation
				if (token[i] == operation[0]) {
					return 1;
				} else if (strcmp(operation, EXECUTE) == 0) {
					if (token[i] == operation[1]) {
						return 1;
					}
				}
			}
			return 0;
		}
		token = strtok(NULL, ",");
	}
	return 0;
}

// Validates the action the client wants to do
validate_action_return *
validate_action_1_svc(action_param *argp, struct svc_req *rqstp)
{
	static validate_action_return result;
	char *acces_token = argp->access_token;

	if (strcmp(acces_token, NOT_FOUND) == 0) { //access token is not found
		result.result = "PERMISSION_DENIED";
		result.acces_token = acces_token;
		result.refresh_token = "NONE";
		result.id_client = argp->id;
		printf("DENY (%s,%s,,0)\n", argp->operation_type, argp->resource);
		return &result;
	}
	char *id = argp->id;
	client *client = check_id(id);

	// Check if access_token is the same as in the database
	if (strcmp(client->access_token, acces_token) != 0) {
		result.result = "PERMISSION_DENIED";
	} else {
		// Regenerate new tokens if refresh is active
		if (client->valability == 0 && client->refresh == 1) {
			refresh_change new_tokens = refresh(client->refresh_token, id);
			client->access_token = new_tokens.access;
			client->refresh_token = new_tokens.refresh;
			client->valability = max_valability;
		} else if (client->valability == 0) {
			result.result = "TOKEN_EXPIRED";
			printf("DENY (%s,%s,,0)\n", argp->operation_type, argp->resource);
			result.acces_token = acces_token;

			if (client->refresh == 1) {
				result.refresh_token = client->refresh_token;
			} else {
				result.refresh_token = "NONE";
			}
			result.id_client = id;
			return &result;
		}
		char *resource = argp->resource;
		client->valability--;

		// Check if the resource exists + client can use the operation on it
		if (check_resource(resource) == 0) {
			result.result = "RESOURCE_NOT_FOUND";
		} else {
			char *permissions = strdup(client->permissions);
			if (check_permision(argp->operation_type, permissions, resource)
									== 1) {
				result.result = "PERMISSION_GRANTED";
				result.id_client = id;
				result.acces_token = client->access_token;
				if (client->refresh == 1) {
					result.refresh_token = client->refresh_token;
				} else {
					result.refresh_token = "NONE";
				}

				printf("PERMIT (%s,%s,%s,%d)\n", argp->operation_type,
					   argp->resource, client->access_token,
					   client->valability);
				fflush(NULL);
				return &result;
			}
			result.result = "OPERATION_NOT_PERMITTED";
		}
	}
	// Operation is denied
	printf("DENY (%s,%s,%s,%d)\n", argp->operation_type, argp->resource,
		   client->access_token, client->valability);
	result.id_client = id;
	result.acces_token = client->access_token;

	// Can't return null value -> we put NONE if refresh is not active
	if (client->refresh == 1) {
		result.refresh_token = client->refresh_token;
	} else {
		result.refresh_token = "NONE";
	}
	fflush(NULL);
	return &result;
}

// Function to approve a client
approve_req_token_return *
approve_token_1_svc(char **argp, struct svc_req *rqstp)
{
	static approve_req_token_return  result;
	char *aproved_tokens_line = malloc(200 * sizeof(char));
	FILE *f_aprob = fopen(aprob_file, "r");
	if (!f_aprob) {
		perror("Error opening file");
		exit(1);
	}
	int counter = 0;

	// Goes through the file to find the specific line that has the aproval
	while (counter <= request_counter) {
		fgets(aproved_tokens_line, 200, f_aprob);
		counter++;
	}

	// We compare to see if the string is the one that says if it's not approved
	if (strcmp(aproved_tokens_line, NOT_APROVED) == 0) {
		result.access_token = *argp;
		result.permisions = "NONE";
		result.approved = 0;
	} else {
		result.access_token = *argp;
		result.permisions = strtok(aproved_tokens_line, "\n");
		result.approved = 1;
	}

	// We add another request to the counter
	request_counter++;
	fclose(f_aprob);
	return &result;
}

// Generate access token with refresh active
req_access_refresh_return *
req_access_refr_1_svc(req_access_param *argp, struct svc_req *rqstp)
{
	static req_access_refresh_return  result;

	// Grab the client from the database based on id
	client *client = check_id(argp->id);

	// Fills up the result variable with all the data needed
	result.id = argp->id;
	result.auth_token = argp->auth_token;
	result.access_token = generate_access_token(argp->auth_token);
	result.refresh_token = generate_access_token(result.access_token);

	// Fills up the client variable with all the data generated
	client->access_token = result.access_token;
	client->valability = max_valability;
	client->refresh_token = result.refresh_token;
	client->refresh = 1;

	printf("  AccessToken = %s\n", result.access_token);
	printf("  RefreshToken = %s\n", result.refresh_token);
	fflush(NULL);
	return &result;
}
