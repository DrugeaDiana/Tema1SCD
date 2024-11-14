struct req_authorization_return{
    string id<>;
    string auth_token<>;
    int valid;
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

struct action_param{
    string operation_type<>;
    string resource<>;
    string access_token<>;
};

struct approve_req_token_return{
    string access_token<>;
    string permisions<>;
    int approved;
};

program TEMA1PROG {
    version TEMA1VERS {
        req_authorization_return REQ_AUTH(string id) = 1;
        req_access_return REQ_ACCESS(req_access_param) = 2;
        string VALIDATE_ACTION(action_param) = 3;
        approve_req_token_return APPROVE_TOKEN(string auth_token) = 4;

    } = 1;
} = 0x31122002;