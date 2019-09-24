#include "service_net.h"
#include "utility_tool.h"
#include <chrono>
#include "server_sip.h"

#define BUFFER_MAX 4048

service_net::service_net(const unsigned int &port) : m_port(port)
{
}

bool service_net::start()
{
    mp_context = std::make_shared<context_ptr::element_type>();
    m_thread = std::thread(std::bind(service_net::handle_thread, mp_context));
    boost::asio::spawn(*mp_context, std::bind(service_net::start_acceptor, m_port, mp_context, std::placeholders::_1));
    return true;
}

void service_net::stop()
{
    auto p_context = mp_context;
    mp_context.reset();
    if(p_context){
        p_context->stop();
    }
    m_thread.join();
}

bool service_net::start_acceptor(unsigned int port, context_ptr p_context, boost::asio::yield_context yield){
    /*
    try{
        //auto p_server_sip = std::make_shared<server_sip>();
        auto p_socket = std::make_shared<socket_ptr::element_type>(*p_context, point_type(boost::asio::ip::address(), static_cast<unsigned short>(port)));
        point_type point_sender;
        boost::system::error_code ec;
        std::size_t count = 0;
        while(true){
            auto p_frame = std::make_shared<frame_ptr::element_type>(BUFFER_MAX, 0x00);
            count = p_socket->async_receive_from(boost::asio::buffer(*p_frame, BUFFER_MAX), point_sender, yield[ec]);
            if(ec){
                LOG_ERROR("接收数据时发生错误:"<<ec.message());
                break;
            }
            LOG_DEBUG("收到数据:"<<std::string(reinterpret_cast<char*>(p_frame->data())));

            p_server_sip->on_read(p_frame, count, point_sender, p_socket, p_context);
        }
        
    }catch(const std::exception& e){
        LOG_ERROR("接收连接时发生错误:"<<e.what());
    }
    */
    return true;
}

void service_net::handle_thread(context_ptr p_context)
{
    LOG_INFO("服务线程开始运行");
    while (true)
    {
        try
        {
            boost::asio::io_context::work work(*p_context);
            p_context->run();
            break;
        }
        catch (const std::exception &e)
        {
            LOG_ERROR("服务线程出现错误:" << e.what());
        }
        std::this_thread::sleep_for(std::chrono::seconds(60));
        LOG_INFO("重启服务线程");
    }
    LOG_INFO("服务线程结束运行");
}
