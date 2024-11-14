#include "tema1.h"
#include <stdio.h> 
#include <time.h> 
#include <rpc/rpc.h>
#include "token.h"
#define NOT_APROVED "*,-\n"

typedef struct {
	char *id;
	char *auth_token;
	char *access_token;
	char *refresh_token;
	int valability;
	int approved;
	char *permissions;
}	client;

char **resources;
client **clients;
char **aproved_tokens;
int max_valability;
int nr_clients;
int request_counter = 0;
char *aprob_file;
void init_server(int argc, char **argv) {
	FILE *f_id = fopen(argv[1], "r");
	if (f_id == NULL) {
		perror("Error opening file");
		exit(1);
	}
	char *line = malloc(20 * sizeof(char));
	fgets(line, 20, f_id);
	nr_clients = atoi(line);
	clients = malloc(nr_clients * sizeof(client*));
	for (int i = 0; i < nr_clients; i++) {
		clients[i] = malloc(sizeof(client));
		fgets(line, 17, f_id);
		clients[i]->id = malloc(17 * sizeof(char));
		char *token = strtok(line, "\n");
		strcpy(clients[i]->id, token);
	}
	fclose(f_id);
	free(line);

	char *res_line = malloc(100 * sizeof(char));
	FILE *f_res = fopen(argv[2], "r");
	if (f_res == NULL) {
		perror("Error opening file");
		exit(1);
	}
	fgets(res_line, 16, f_res);
	int nr_res = atoi(res_line);
	resources = malloc(nr_res * sizeof(char*));
	for (int i = 0; i < nr_res; i++) {
		resources[i] = malloc(100 * sizeof(char));
		fgets(res_line, 100, f_res);
		strcpy(resources[i], res_line);
	}
	aprob_file = argv[3];
	fclose(f_res);
	free(res_line);


	max_valability = atoi(argv[4]);
	printf("Server initialized\n");
	for (int i = 0; i < nr_clients; i++) {
		printf("Clientul: %s\n", clients[i]->id);
	}
	printf("\n");

}

client* check_id(char *id) {
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

	/*
	 * insert server code here
	 */
	printf("BEGIN %s AUTHZ\n", *argp);
	client *client = check_id(*argp);
	if (client == NULL) {
		printf("USER_NOT_FOUND\n");
		result.id = *argp;
		result.auth_token = *argp;
		result.valid = -1;
		return &result;
	}
	result.id = *argp;
	result.auth_token = generate_access_token(*argp);
	result.valid = 1;
	client->auth_token = result.auth_token;

	printf("\t RequestToken = %s\n", result.auth_token);
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

	/*
	 * insert server code here
	 */
	client *client = check_id(argp->id);
	if (client == NULL) {
		printf("USER_NOT_FOUND\n");
		return NULL;
	}
	result.id = argp->id;
	result.auth_token = argp->auth_token;
	result.access_token = generate_access_token(argp->id);
	client->access_token = result.access_token;
	printf("\t AccessToken = %s\n", result.access_token);
	
	return &result;
}

char **
validate_action_1_svc(action_param *argp, struct svc_req *rqstp)
{
	static char * result;

	/*
	 * insert server code here
	 */

	return &result;
}

approve_req_token_return *
approve_token_1_svc(char **argp, struct svc_req *rqstp)
{
	static approve_req_token_return  result;
	
	char *aproved_tokens_line = malloc(200 * sizeof(char));
	FILE *f_aprob = fopen(aprob_file, "r");
	if (f_aprob == NULL) {
		perror("Error opening file");
		exit(1);
	}
	int counter = 0;
	while(counter <= request_counter) {
		fgets(aproved_tokens_line, 200, f_aprob);
		counter++;
	}
	if (strcmp(aproved_tokens_line, NOT_APROVED)== 0) {
		result.access_token = *argp;
		result.permisions = "NONE";
		result.approved = 0;
	} else {
		result.access_token = *argp;
		result.permisions = aproved_tokens_line;
		result.approved = 1;
	}
	request_counter++;
	
	return &result;
}
