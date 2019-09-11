#ifndef ADAPTER_GB28181_H
#define ADAPTER_GB28181_H

#include "plugin.h"
#include <map>
#include <vector>

class adapter_gb28181 : public plugin, public std::enable_shared_from_this<adapter_gb28181>
{
public:
    class info_net_proxy{
    public:
        std::vector<info_param_ptr> params;
        point_type point;
        socket_ptr p_socket;
        context_ptr p_context;
        std::string status;
    };
    typedef std::shared_ptr<info_net_proxy> info_net_proxy_ptr;

    virtual ~adapter_gb28181();
    virtual int do_work(info_net_proxy_ptr p_proxy);
    virtual void on_read(frame_ptr& p_frame, std::size_t& count, point_type& point, socket_ptr& p_socket, context_ptr& p_context);
protected:
    virtual int send_frame(frame_ptr p_frame, info_net_proxy_ptr p_info);
    virtual std::string ptime_to_param_date(const boost::posix_time::ptime& time);
    virtual int send_frame(const std::string& data, info_net_proxy_ptr p_info);
    virtual int decode(info_param_ptr& p_param, frame_ptr& p_frame);
    virtual std::string random_str();
    virtual bool find_line(const char** pp_line_start, const char** pp_line_end, const char** pp_start, const char* p_end);
    virtual bool find_param(const char** pp_param_start, const char** pp_param_end, const char** pp_start, const char* p_end, const char s);
    virtual bool remove_char(const char** pp_start, const char** pp_end, const char s);
    virtual bool remove_rn(const char** pp_start, const char** pp_end);
    virtual bool decode_kv(std::map<std::string, std::string>& kv, const std::string& tag, const char **pp_line_start, const char *p_line_end, const char s);

    std::map<std::string, info_net_proxy_ptr> m_proxys;
    std::string m_realm = "123456";
};
typedef std::shared_ptr<adapter_gb28181> adapter_gb28181_ptr;

#endif // ADAPTER_GB28181_H
