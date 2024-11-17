/* Request Authorization Struct -> return for the function */
/* Valid -> wether or not the client actually exists in the database */
/* Approved -> if the client was approved or not */
/* Id -> the client's id */
/* Auth_token -> token used for Authorization */
struct req_authorization_return{
    string id<>;
    string auth_token<>;
    int valid;
    int approved;
};

/* Request Access Authorization With and Without Refresh Structs */
/* Struct used for the parameters of the function */
struct req_access_param{
    string id<>;
    string auth_token<>;
};

/* Return for when we don't have refresh activated */
struct req_access_return{
    string id<>;
    string auth_token<>;
    string access_token<>;
};

/* Return for when we have refresh activated */
struct req_access_refresh_return {
    string id<>;
    string auth_token<>;
    string access_token<>;
    string refresh_token<>;
};

/* Validate_action structs */
struct action_param{
    string id<>;
    string operation_type<>;
    string resource<>;
    string access_token<>;
};

/* Return for validate action */
/* Has fields for refresh in case the tokens can and need to be refreshed */
struct validate_action_return{
    string id_client<>;
    string acces_token<>;
    string refresh_token<>;
    string result<>;
};

/* Return for aproving a client */
/* Gives the list of permisions of the client as well */
/* Approved -> 0 if the client is not approved, 1 if it is. */
struct approve_req_token_return{
    string access_token<>;
    string permisions<>;
    int approved;
};

program TEMA1PROG {
    version TEMA1VERS {
        req_authorization_return REQ_AUTH(string id) = 1;
        req_access_return REQ_ACCESS(req_access_param) = 2;
        validate_action_return VALIDATE_ACTION(action_param) = 3;
        approve_req_token_return APPROVE_TOKEN(string auth_token) = 4;
        req_access_refresh_return REQ_ACCESS_REFR(req_access_param) = 5;
    } = 1;
} = 0x31122002;