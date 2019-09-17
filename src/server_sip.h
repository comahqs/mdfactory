#ifndef SERVER_SIP_H
#define SERVER_SIP_H

#include "plugin.h"
#include <map>
#include <vector>



class server_sip : public plugin, public std::enable_shared_from_this<server_sip>
{
public:
    virtual ~server_sip();
    virtual void on_read(frame_ptr& p_frame, std::size_t& count, point_type& point, socket_ptr& p_socket, context_ptr& p_context);
protected:
     virtual int do_work(info_net_ptr p_proxy);
    virtual int send_frame(frame_ptr p_frame, info_net_ptr p_info);
    virtual std::string ptime_to_param_date(const boost::posix_time::ptime& time);
    virtual int send_frame(const std::string& data, info_net_ptr p_info);
    virtual int decode(info_param_ptr& p_param, frame_ptr& p_frame);
    virtual std::string random_str();
    virtual bool find_line(const char** pp_line_start, const char** pp_line_end, const char** pp_start, const char* p_end);
    virtual bool find_param(const char** pp_param_start, const char** pp_param_end, const char** pp_start, const char* p_end, const char s);
    virtual bool remove_char(const char** pp_start, const char** pp_end, const char s);
    virtual bool remove_rn(const char** pp_start, const char** pp_end);
    virtual bool decode_kv(std::map<std::string, std::string>& kv, const std::string& tag, const char **pp_line_start, const char *p_line_end, const char s);
    virtual bool decode_kv(tinyxml2::XMLElement* p_parent, const std::string& tag, const char **pp_line_start, const char *p_line_end, const char s, tinyxml2::XMLDocument *pdoc);
    virtual int encode_header(std::stringstream& stream, const int& code, const std::string& action, const info_param_ptr& p_param, const info_net_ptr& p_info);
    virtual tinyxml2::XMLElement* put_node(tinyxml2::XMLElement* p_parent, const char* pname, const char *pvalue_start, const char *pvalue_end, tinyxml2::XMLDocument *pdoc);
    virtual tinyxml2::XMLElement* put_node(tinyxml2::XMLElement* p_parent, const char* pname_start, const char* pname_end, const char *pvalue_start, const char *pvalue_end, tinyxml2::XMLDocument *pdoc);
    virtual bool find_node_value(std::string& v, const char* pname, tinyxml2::XMLElement* p_node);
    virtual bool find_node_value(std::string& v, const char* pname_first, const char* pname_second, tinyxml2::XMLElement* p_node);
    virtual std::string find_node_value(const char* pname, tinyxml2::XMLElement* p_node);
    virtual int decode_sdp(info_param_ptr& p_param, const char** pp_start, const char** pp_end);
    virtual bool encode_request(std::stringstream& stream, const std::string& action, const std::string& sip_desc, const std::string& number_src, const std::string& address_src, const std::string& content_type = "", const std::string& content_data = "");
    virtual std::string random_branch();
    virtual std::string random_tag();


    std::map<std::string, info_net_ptr> m_proxys;
    std::string m_realm = "123456";
};
typedef std::shared_ptr<server_sip> server_sip_ptr;

#endif // SERVER_SIP_H
