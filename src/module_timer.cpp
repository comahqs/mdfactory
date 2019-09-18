#include "module_timer.h"
#include "utility_tool.h"
#include "error_code.h"
#include <boost/bind.hpp>

module_timer::module_timer(boost::asio::io_context& context, std::function<void ()> fun_cancel, const int64_t& time_resend, const int64_t& time_cancel)
    :m_fun(fun_cancel), m_time_resend(time_resend), m_time_cancel(time_cancel)
{
    mp_timer_send = std::make_shared<timer_ptr::element_type>(context);
    mp_timer_cancel = std::make_shared<timer_ptr::element_type>(context);
}

module_timer::~module_timer(){

}

void module_timer::restart(){
    mp_timer_send->cancel();
    mp_timer_cancel->cancel();

    mp_timer_cancel->expires_from_now(boost::posix_time::seconds(m_time_cancel));
    mp_timer_cancel->async_wait(boost::bind(module_timer::handle_cancel, _1, m_fun));
}

void module_timer::send_buffer(std::shared_ptr<std::string> pbuffer, point_type point, socket_ptr psocket, int count){
    send(pbuffer, point, psocket);

    mp_timer_send->cancel();
    mp_timer_cancel->cancel();

    mp_timer_cancel->expires_from_now(boost::posix_time::seconds(m_time_cancel));
    mp_timer_cancel->async_wait(boost::bind(module_timer::handle_cancel, _1, m_fun));

    if(0 >= count){
        return;
    }
    mp_timer_send->expires_from_now(boost::posix_time::seconds(m_time_resend));
    mp_timer_send->async_wait(boost::bind(module_timer::handle_resend, _1, pbuffer, point, psocket, mp_timer_send, m_time_resend, 2));
}

void module_timer::send(std::shared_ptr<std::string> p_buffer, point_type point, socket_ptr p_socket){
    p_socket->async_send_to(boost::asio::buffer(p_buffer->c_str(), p_buffer->size()), point, [p_buffer, point, p_socket](const boost::system::error_code& e, const std::size_t& ){
        if(e){
            LOG_ERROR("发送数据时发生错误:"<<e.message());
        }
    });
}

void module_timer::handle_cancel(const boost::system::error_code& ec, std::function<void ()> fun){
    if(ec){
        return;
    }
    fun();
}

void module_timer::handle_resend(const boost::system::error_code& ec, std::shared_ptr<std::string> pbuffer, point_type point, socket_ptr psocket, timer_ptr ptimer, int64_t time_resend, int count){
    if(ec){
        return;
    }
    if(0 >= count){
        return;
    }
    --count;
    send(pbuffer, point, psocket);
    ptimer->expires_from_now(boost::posix_time::seconds(time_resend));
    ptimer->async_wait(boost::bind(module_timer::handle_resend, _1, pbuffer, point, psocket, ptimer, time_resend, count));
}
