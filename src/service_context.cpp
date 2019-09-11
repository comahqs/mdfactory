#include "service_context.h"
#include "utility_tool.h"


bool service_context::start_before(){
    return true;
}

void service_context::stop_after(){
    for(auto& p_context : m_contexts){
        p_context->stop();
    }
    m_contexts.clear();
    for(auto& t : m_threads){
        t.join();
    }
    m_threads.clear();
}


context_ptr service_context::get_context(){
    return create_context();
}

context_ptr service_context::create_context(){
    auto p_context = std::make_shared<context_ptr::element_type>();
    m_threads.push_back(boost::thread(boost::bind(service_context::handle_thread, p_context)));
    m_contexts.push_back(p_context);
    return p_context;
}

void service_context::handle_thread(context_ptr p_context){
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

