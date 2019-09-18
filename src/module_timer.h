#ifndef MODULE_TIMER_H
#define MODULE_TIMER_H

#include "plugin.h"

class module_timer : public i_timer, public std::enable_shared_from_this<module_timer>
{
public:
    typedef std::shared_ptr<boost::asio::deadline_timer> timer_ptr;

    module_timer(boost::asio::io_context& context, std::function<void ()> fun_cancel, const int64_t& time_resend, const int64_t& time_cancel = 0);
    virtual ~module_timer();

    virtual void restart();
    virtual void send_buffer(std::shared_ptr<std::string> pbuffer, point_type point, socket_ptr psocket, int count);

protected:
    static void handle_cancel(const boost::system::error_code& ec, std::function<void ()> fun);
    static void handle_resend(const boost::system::error_code& ec, std::shared_ptr<std::string> pbuffer, point_type point, socket_ptr psocket, timer_ptr ptimer, int64_t time_resend, int count);
    static void send(std::shared_ptr<std::string> p_buffer, point_type point, socket_ptr p_socket);

    std::shared_ptr<std::string> mp_buffer;
    point_type m_point;
    socket_ptr mp_socket;
    std::function<void ()> m_fun;
    int64_t m_time_resend;
    int64_t m_time_cancel;
    timer_ptr mp_timer_send;
    timer_ptr mp_timer_cancel;
};
typedef std::shared_ptr<module_timer> module_timer_ptr;

#endif // MODULE_TIMER_H
