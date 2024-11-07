struct id_client{
    string id[15];
};

struct req_access_param{
    string id[15];
    string auth_token[15];
};

struct action_param{
    string operation_type<>;
    string resource<>;
    string access_token[15];
}

