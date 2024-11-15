struct req_authorization_return{
    string id<>;
    string auth_token<>;
    int valid;
    int approved;
};

struct req_access_param{
    string id<>;
    string auth_token<>;
};

struct req_access_return{
    string id<15>;
    string auth_token<>;
    string access_token<>;
};

struct req_access_refresh_return {
    string id<15>;
    string auth_token<>;
    string access_token<>;
    string refresh_token<>;
};

struct action_param{
    string id<>;
    string operation_type<>;
    string resource<>;
    string access_token<>;
};

struct approve_req_token_return{
    string access_token<>;
    string permisions<>;
    int approved;
};

struct validate_action_return{
    string id_client<>;
    string acces_token<>;
    string refresh_token<>;
    string result<>;
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