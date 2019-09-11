#ifndef SERVICE_NET_H__
#define SERVICE_NET_H__

#include "plugin.h"
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <thread>

class service_net : public plugin{
public:
    
    typedef std::shared_ptr<boost::asio::ip::udp::socket> socket_ptr;
    typedef boost::asio::ip::udp::endpoint point_type;

    service_net(const unsigned int& port);

    virtual bool start();
    virtual void stop();
protected:
    static void handle_thread(context_ptr p_context);

    static bool start_acceptor(unsigned int port, context_ptr p_context, boost::asio::yield_context yield);

    context_ptr mp_context;
    unsigned int m_port = 0;
    std::thread m_thread;
};
typedef std::shared_ptr<service_net> service_net_ptr;








#endif