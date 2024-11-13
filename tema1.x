struct req_authorization_return{
    char id<15>;
    char auth_token<15>;
};

struct req_access_param{
    char id<15>;
    char auth_token<15>;
};

struct req_access_return{
    char id<15>;
    char auth_token<15>;
    char access_token<15>;
};

struct action_param{
    string operation_type<>;
    string resource<>;
    char access_token<15>;
};

struct approve_req_token_return{
    char access_token[15];
    char permisions<>;
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