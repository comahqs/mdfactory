#ifndef MODULE_SIP_H
#define MODULE_SIP_H

#include "plugin.h"

#define STATUS_END "__END"

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

class module_sip : public std::enable_shared_from_this<module_sip>
{
public:
    virtual ~module_sip();

    virtual bool get_transaction_id(std::string& id, info_param_ptr p_param);
    virtual void do_work(info_param_ptr p_param, info_transaction_ptr p_transaction);
    virtual int decode(info_param_ptr& p_param, frame_ptr& p_frame);
    virtual bool add_server(const std::string& number, socket_ptr p_socket, point_type point, const std::string& type = "");
protected:
    virtual int do_register(info_param_ptr p_param, info_transaction_ptr p_transaction);
    virtual int do_message(info_param_ptr p_param, info_transaction_ptr p_transaction);
    virtual int do_message_keepalive(info_param_ptr p_param, info_transaction_ptr p_transaction);
    virtual int do_invite(info_param_ptr p_param, info_transaction_ptr p_transaction);
    virtual bool split(std::vector<std::string>& params, const std::string& data, const char s);
    virtual bool get_value(std::string& v, const std::string& data, const char s, const std::string& k);
    virtual bool get_value(std::string& v, const std::string& data, const char s, const std::size_t index);
    virtual void remove_char(std::string& v, const char s);
    virtual info_param_ptr create_response_by_request(const int& code, const std::string& action, info_param_ptr p_request);
    virtual info_param_ptr create_request_by_request(info_param_ptr prequest_old, const std::string& action, info_server_ptr pserver_src, info_server_ptr pserver_desc);
    virtual std::shared_ptr<std::string> create_buffer(info_param_ptr p_response);
    virtual int send_buffer(std::shared_ptr<std::string> p_buffer, point_type point, socket_ptr p_socket);
    virtual std::string ptime_to_register_date(const boost::posix_time::ptime& time);
    virtual info_server_ptr find_server_by_number(const std::string& number);
    virtual info_server_ptr find_server_by_type(const std::string& type);
    virtual bool is_confirm(const int& code, const std::string& action, info_param_ptr p_param);
    virtual bool is_response(info_param_ptr presponse, info_param_ptr prequest);
    virtual std::string random_tag();
    virtual std::string get_number(const std::string& v);
    virtual bool find_line(const char **pp_line_start, const char **pp_line_end, const char **pp_start, const char *p_end);
    virtual bool find_param(const char **pp_param_start, const char **pp_param_end, const char **pp_start, const char *p_end, const char s);
    virtual bool remove_char(const char **pp_start, const char **pp_end, const char s);
    virtual std::string random_once();
    virtual bool find_node_value(std::string& v, const char* pname, tinyxml2::XMLElement* pnode);
    virtual bool find_node_value(std::string& v, const char* pname_first, const char* pname_second, tinyxml2::XMLElement* pnode);

    std::map<std::string, info_server_ptr> m_servers;
    std::string m_realm = "123456";
};
typedef std::shared_ptr<module_sip> module_sip_ptr;

#endif // MODULE_SIP_H
