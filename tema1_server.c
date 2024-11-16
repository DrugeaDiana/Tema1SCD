#include "tema1.h"
#include <stdio.h>
#include <time.h>
#include <rpc/rpc.h>
#include "token.h"

#define NOT_APROVED "*,-\n"
#define NOT_FOUND "NOT_FOUND"
#define EXECUTE "EXECUTE"

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

char **resources;
client **clients;
char **aproved_tokens;
int max_valability;
int nr_clients;
int nr_res;
int request_counter;
char *aprob_file;

void init_server(int argc, char **argv)
{
	FILE *f_id = fopen(argv[1], "r");
	if (!f_id) {
		perror("Error opening file");
		exit(1);
	}

	char *line = malloc(20 * sizeof(char));
	fgets(line, 20, f_id);
	nr_clients = atoi(line);
	clients = malloc(nr_clients * sizeof(client *));

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

	fgets(res_line, 16, f_res);
	nr_res = atoi(res_line);
	resources = malloc(nr_res * sizeof(char *));

	for (int i = 0; i < nr_res; i++) {
		resources[i] = malloc(100 * sizeof(char));
		fgets(res_line, 100, f_res);
		char *token = strtok(res_line, "\n");
		resources[i] = strdup(token);
	}
	aprob_file = argv[3];
	fclose(f_res);
	free(res_line);

	max_valability = atoi(argv[4]);
	request_counter = 0;
}

client *check_id(char *id)
{
	for (int i = 0; i < nr_clients; i++) {
		if (strcmp(clients[i]->id, id) == 0) {
			return clients[i];
		}
	}
	return NULL;
}

req_authorization_return *
req_auth_1_svc(char **argp, struct svc_req *rqstp)
{
	static req_authorization_return  result;

	printf("BEGIN %s AUTHZ\n", *argp);
	client *client = check_id(*argp);
	if (!client) {
		result.id = *argp;
		result.auth_token = *argp;
		result.valid = -1;
		return &result;
	}
	result.id = *argp;
	result.auth_token = generate_access_token(*argp);
	result.valid = 1;
	client->auth_token = result.auth_token;

	printf("  RequestToken = %s\n", result.auth_token);
	approve_req_token_return *approve;
	approve = approve_token_1_svc(&result.auth_token, rqstp);
	if (approve->approved == 0) {
		result.approved = 0;
	} else {
		result.approved = 1;
	}
	client->permissions = approve->permisions;

	client->approved = result.approved;
	return &result;
}

req_access_return *
req_access_1_svc(req_access_param *argp, struct svc_req *rqstp)
{
	static req_access_return  result;

	client *client = check_id(argp->id);

	result.id = argp->id;
	result.auth_token = argp->auth_token;
	result.access_token = generate_access_token(argp->auth_token);
	client->access_token = result.access_token;
	client->valability = max_valability;
	printf("  AccessToken = %s\n", result.access_token);
	client->refresh = 0;
	fflush(NULL);
	return &result;
}

int check_resource(char *resource)
{
	for (int i = 0; i < nr_res; i++) {
		if (strcmp(resources[i], resource) == 0) {
			return 1;
		}
	}
	return 0;
}

typedef struct {
	char *refresh;
	char *access;
} refresh_change;

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

int check_permision(char *operation, char *permissions, char *resource)
{
	char *token = strtok(permissions, ",");
	while (token) {
		if (strcmp(token, resource) == 0) {
			token = strtok(NULL, ",");
			for (int i = 0; i < strlen(token); i++) {
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

validate_action_return *
validate_action_1_svc(action_param *argp, struct svc_req *rqstp)
{
	static validate_action_return result;
	char *acces_token = argp->access_token;
	if (strcmp(acces_token, NOT_FOUND) == 0) {
		result.result = "PERMISSION_DENIED";
		result.acces_token = acces_token;
		result.refresh_token = "NONE";
		result.id_client = argp->id;
		printf("DENY (%s,%s,,0)\n", argp->operation_type, argp->resource);
		return &result;
	}
	char *id = argp->id;
	client *client = check_id(id);
	if (strcmp(client->access_token, acces_token) != 0) {
		result.result = "PERMISSION_DENIED";
	} else {
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
	printf("DENY (%s,%s,%s,%d)\n", argp->operation_type, argp->resource,
		   client->access_token, client->valability);
	result.id_client = id;
	result.acces_token = client->access_token;
	if (client->refresh == 1) {
		result.refresh_token = client->refresh_token;
	} else {
		result.refresh_token = "NONE";
	}
	fflush(NULL);
	return &result;
}

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
	while (counter <= request_counter) {
		fgets(aproved_tokens_line, 200, f_aprob);
		counter++;
	}
	if (strcmp(aproved_tokens_line, NOT_APROVED) == 0) {
		result.access_token = *argp;
		result.permisions = "NONE";
		result.approved = 0;
	} else {
		result.access_token = *argp;
		result.permisions = strtok(aproved_tokens_line, "\n");
		result.approved = 1;
	}
	request_counter++;
	return &result;
}

req_access_refresh_return *
req_access_refr_1_svc(req_access_param *argp, struct svc_req *rqstp)
{
	static req_access_refresh_return  result;

	client *client = check_id(argp->id);

	result.id = argp->id;
	result.auth_token = argp->auth_token;
	result.access_token = generate_access_token(argp->auth_token);
	client->access_token = result.access_token;
	client->valability = max_valability;
	result.refresh_token = generate_access_token(client->access_token);
	client->refresh_token = result.refresh_token;
	client->refresh = 1;
	printf("  AccessToken = %s\n", result.access_token);
	printf("  RefreshToken = %s\n", result.refresh_token);
	fflush(NULL);
	return &result;

}
