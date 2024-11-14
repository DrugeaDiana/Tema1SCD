#include "tema1.h"
#include <stdio.h> 
#include <time.h> 
#include <rpc/rpc.h>
#include "token.h"

typedef struct {
	char *id;
	char *auth_token;
	char *access_token;
	char *refresh_token;
	int valability;
	char *permissions;
}	client;

char **resources;
client **clients;
char **aproved_tokens;
int max_valability;

void init_server(int argc, char **argv) {
	FILE *f_id = fopen(argv[1], "r");
	if (f_id == NULL) {
		perror("Error opening file");
		exit(1);
	}
	char *line = malloc(10 * sizeof(char));
	fgets(line, 10, f_id);
	int nr_clients = atoi(line);
	clients = malloc(nr_clients * sizeof(client*));
	for (int i = 0; i < nr_clients; i++) {
		clients[i] = malloc(sizeof(client));
		fgets(line, 10, f_id);
		clients[i]->id = malloc(10 * sizeof(char));
		strcpy(clients[i]->id, line);
	}
	fclose(f_id);

	FILE *f_res = fopen(argv[2], "r");
	if (f_res == NULL) {
		perror("Error opening file");
		exit(1);
	}
	line = malloc(10 * sizeof(char));
	fgets(line, 10, f_res);
	int nr_res = atoi(line);
	resources = malloc(nr_res * sizeof(char*));
	for (int i = 0; i < nr_res; i++) {
		resources[i] = malloc(10 * sizeof(char));
		fgets(line, 10, f_res);
		strcpy(resources[i], line);
	}
	fclose(f_res);

	FILE *f_aprob = fopen(argv[3], "r");
	if (f_aprob == NULL) {
		perror("Error opening file");
		exit(1);
	}
	line = malloc(10 * sizeof(char));
	fgets(line, 10, f_aprob);
	int nr_aprob = atoi(line);
	for (int i = 0; i < nr_aprob; i++) {
		fgets(line, 10, f_aprob);
		aproved_tokens[i] = malloc(10 * sizeof(char));
		strcpy(aproved_tokens[i], line);
	}
	fclose(f_aprob);
	free(line);
	max_valability = atoi(argv[4]);
	printf("Server initialized\n");


}

client* check_id(char *id) {
	for (int i = 0; i < sizeof(clients); i++) {
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
	
	result.id = *argp;
	result.auth_token = generate_access_token(*argp);
	printf("BEGIN %s AUTHZ\n", result.id);
	printf("\t RequestToken = %s\n", result.auth_token);
	
	return &result;
}

req_access_return *
req_access_1_svc(req_access_param *argp, struct svc_req *rqstp)
{
	static req_access_return  result;

	/*
	 * insert server code here
	 */
	result.id = argp->id;
	result.auth_token = argp->auth_token;
	result.access_token = generate_access_token(argp->id);

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
	printf("Approved\n");
	result.access_token = *argp;
	result.approved = 1;
	
	/*
	 * insert server code here
	 */

	return &result;
}
