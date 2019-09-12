#ifndef VIRSUAL_CLIENT_H
#define VIRSUAL_CLIENT_H

#include <memory>
#include "plugin.h"
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

class virsual_client : public plugin
{
public:
    virsual_client(const std::string& ip, const unsigned int& port, context_ptr p_context);

    virtual void play();

protected:
    virtual void handle_play(boost::asio::yield_context yield);

    socket_ptr mp_socket;
    std::string m_ip;
    unsigned int m_port;
    context_ptr mp_context;
};

#endif // VIRSUAL_CLIENT_H
