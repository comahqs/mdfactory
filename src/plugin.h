#ifndef PLUGIN_H
#define PLUGIN_H

#include <memory>
#include <functional>
#include <vector>
#include <boost/asio.hpp>
#include <boost/shared_array.hpp>
#include "tinyxml2.h"

typedef std::shared_ptr<std::vector<unsigned char>> frame_ptr;
typedef std::shared_ptr<boost::asio::io_context> context_ptr;
typedef std::shared_ptr<boost::asio::ip::udp::socket> socket_ptr;
typedef boost::asio::ip::udp::endpoint point_type;

class plugin
{
public:
    virtual ~plugin(){}
    virtual bool start_before() { return true; }
    virtual bool start() { return true; }
    virtual bool start_after() { return true; }
    virtual void stop_before() {}
    virtual void stop() {}
    virtual void stop_after() {}
};
typedef std::shared_ptr<plugin> plugin_ptr;


class info_param
{
public:
    std::string header;
    std::string via;
    std::string from;
    std::string to;
    std::string call_id;
    std::string cseq;
    std::string contact;
    std::string content_type;
    std::string max_forwards;
    std::string expires;
    std::string authorization;
    std::string date;
    std::string content;

    socket_ptr p_socket;
    point_type point;
};
typedef std::shared_ptr<info_param> info_param_ptr;

class info_transaction{
public:
    std::string id;
    std::string status;
    std::map<std::string, info_param_ptr> params;
    std::function<int (info_param_ptr, std::shared_ptr<info_transaction>)> fun_work;
};
typedef std::shared_ptr<info_transaction> info_transaction_ptr;


#define NP_SIP "sip"
#define NP_MEDIO "medio"
class i_net_proxy
{
public:
    virtual int read(info_param_ptr &p_param) = 0;
    virtual int write(info_param_ptr &p_param) = 0;
    virtual int notify(const std::string &msg) = 0;
};
typedef std::shared_ptr<i_net_proxy> i_net_proxy_ptr;

#define SM_ANY "*"
class i_state_machine
{
public:
    typedef std::function<int(i_net_proxy_ptr)> callback_type;

    virtual int add_listen(const std::string &msg, callback_type fun) = 0;
};
typedef std::shared_ptr<i_state_machine> i_state_machine_ptr;


class i_service_context
{
public:
    virtual context_ptr get_context() = 0;
    virtual context_ptr create_context() = 0;
};
typedef std::shared_ptr<i_service_context> i_service_context_ptr;

#endif
