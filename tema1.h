/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _TEMA1_H_RPCGEN
#define _TEMA1_H_RPCGEN

#include <rpc/rpc.h>


#ifdef __cplusplus
extern "C" {
#endif


struct req_authorization_return {
	char *id;
	char *auth_token;
	int valid;
	int approved;
};
typedef struct req_authorization_return req_authorization_return;

struct req_access_param {
	char *id;
	char *auth_token;
};
typedef struct req_access_param req_access_param;

struct req_access_return {
	char *id;
	char *auth_token;
	char *access_token;
};
typedef struct req_access_return req_access_return;

struct req_access_refresh_return {
	char *id;
	char *auth_token;
	char *access_token;
	char *refresh_token;
};
typedef struct req_access_refresh_return req_access_refresh_return;

struct action_param {
	char *id;
	char *operation_type;
	char *resource;
	char *access_token;
};
typedef struct action_param action_param;

struct validate_action_return {
	char *id_client;
	char *acces_token;
	char *refresh_token;
	char *result;
};
typedef struct validate_action_return validate_action_return;

struct approve_req_token_return {
	char *access_token;
	char *permisions;
	int approved;
};
typedef struct approve_req_token_return approve_req_token_return;

#define TEMA1PROG 0x31122002
#define TEMA1VERS 1

#if defined(__STDC__) || defined(__cplusplus)
#define REQ_AUTH 1
extern  req_authorization_return * req_auth_1(char **, CLIENT *);
extern  req_authorization_return * req_auth_1_svc(char **, struct svc_req *);
#define REQ_ACCESS 2
extern  req_access_return * req_access_1(req_access_param *, CLIENT *);
extern  req_access_return * req_access_1_svc(req_access_param *, struct svc_req *);
#define VALIDATE_ACTION 3
extern  validate_action_return * validate_action_1(action_param *, CLIENT *);
extern  validate_action_return * validate_action_1_svc(action_param *, struct svc_req *);
#define APPROVE_TOKEN 4
extern  approve_req_token_return * approve_token_1(char **, CLIENT *);
extern  approve_req_token_return * approve_token_1_svc(char **, struct svc_req *);
#define REQ_ACCESS_REFR 5
extern  req_access_refresh_return * req_access_refr_1(req_access_param *, CLIENT *);
extern  req_access_refresh_return * req_access_refr_1_svc(req_access_param *, struct svc_req *);
extern int tema1prog_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

#else /* K&R C */
#define REQ_AUTH 1
extern  req_authorization_return * req_auth_1();
extern  req_authorization_return * req_auth_1_svc();
#define REQ_ACCESS 2
extern  req_access_return * req_access_1();
extern  req_access_return * req_access_1_svc();
#define VALIDATE_ACTION 3
extern  validate_action_return * validate_action_1();
extern  validate_action_return * validate_action_1_svc();
#define APPROVE_TOKEN 4
extern  approve_req_token_return * approve_token_1();
extern  approve_req_token_return * approve_token_1_svc();
#define REQ_ACCESS_REFR 5
extern  req_access_refresh_return * req_access_refr_1();
extern  req_access_refresh_return * req_access_refr_1_svc();
extern int tema1prog_1_freeresult ();
#endif /* K&R C */

/* the xdr functions */

#if defined(__STDC__) || defined(__cplusplus)
extern  bool_t xdr_req_authorization_return (XDR *, req_authorization_return*);
extern  bool_t xdr_req_access_param (XDR *, req_access_param*);
extern  bool_t xdr_req_access_return (XDR *, req_access_return*);
extern  bool_t xdr_req_access_refresh_return (XDR *, req_access_refresh_return*);
extern  bool_t xdr_action_param (XDR *, action_param*);
extern  bool_t xdr_validate_action_return (XDR *, validate_action_return*);
extern  bool_t xdr_approve_req_token_return (XDR *, approve_req_token_return*);

#else /* K&R C */
extern bool_t xdr_req_authorization_return ();
extern bool_t xdr_req_access_param ();
extern bool_t xdr_req_access_return ();
extern bool_t xdr_req_access_refresh_return ();
extern bool_t xdr_action_param ();
extern bool_t xdr_validate_action_return ();
extern bool_t xdr_approve_req_token_return ();

#endif /* K&R C */

#ifdef __cplusplus
}
#endif

#endif /* !_TEMA1_H_RPCGEN */
