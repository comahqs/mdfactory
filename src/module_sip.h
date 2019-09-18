#ifndef MODULE_SIP_H
#define MODULE_SIP_H

#include "plugin.h"


#define SERVER_TYPE_SIP "server_type_sip"
#define SERVER_TYPE_MEDIA "server_type_media"
class info_server{
public:
    std::string id;
    std::string number;
    point_type point;
    socket_ptr p_socket;
    std::string type;
};
typedef std::shared_ptr<info_server> info_server_ptr;

class module_sip
{
public:
    module_sip();

    virtual bool get_transaction_id(std::string& id, info_param_ptr p_param);
    virtual bool split(std::vector<std::string>& params, const std::string& data, const char s);
    virtual bool get_value(std::string& v, const std::string& data, const char s, const std::string& k);
    virtual bool get_value(std::string& v, const std::string& data, const char s, const std::size_t index);
    virtual void remove_char(std::string& v, const char s);

    virtual int do_register(info_param_ptr p_param, info_transaction_ptr p_transaction);
    virtual int do_message(info_param_ptr p_param, info_transaction_ptr p_transaction);
    virtual int do_invite(info_param_ptr p_param, info_transaction_ptr p_transaction);

    virtual bool add_server(const std::string& number, socket_ptr p_socket, point_type point, const std::string& type = "");
protected:
    virtual info_param_ptr create_response_by_request(const int& code, const std::string& action, info_param_ptr p_request);
    virtual std::string get_value(const std::string& data, const char s, const std::size_t index);
    virtual std::shared_ptr<std::string> create_buffer_from_response(info_param_ptr p_response);
    virtual int send_frame(std::shared_ptr<std::string> p_buffer, info_param_ptr p_param);
    virtual std::string ptime_to_register_date(const boost::posix_time::ptime& time);
    virtual info_server_ptr find_server_by_number(const std::string& number);
    virtual info_server_ptr find_server_by_type(const std::string& type);

    std::map<std::string, info_server_ptr> m_servers;
};
typedef std::shared_ptr<module_sip> module_sip_ptr;

#endif // MODULE_SIP_H
