#ifndef STATE_MACHINE_H__
#define STATE_MACHINE_H__

#include "plugin.h"
#include <map>
#include <vector>
#include "protocol_gb28181.h"

class state_machine : public plugin, public std::enable_shared_from_this<state_machine>
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

    virtual int notify(info_net_proxy_ptr p_proxy);
    virtual void on_read(frame_ptr& p_frame, std::size_t& count, point_type& point, socket_ptr& p_socket, context_ptr& p_context);
protected:
    virtual int send_frame(frame_ptr p_frame, info_net_proxy_ptr p_info);
    virtual std::string ptime_to_param_date(const boost::posix_time::ptime& time);

    std::map<std::string, info_net_proxy_ptr> m_proxys;
    protocol_gb28181_ptr mp_protocol = std::make_shared<protocol_gb28181>();
    std::string m_realm = "123456";
};
typedef std::shared_ptr<state_machine> state_machine_ptr;

#endif // STATE_MACHINE_H__