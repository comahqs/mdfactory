#include "state_machine.h"
#include "utility_tool.h"
#include "error_code.h"
#include <boost/format.hpp>

#define STATUS_REGISTER_1 "REGISTER@1"
#define STATUS_REGISTER_3 "REGISTER@3"

void state_machine::on_read(frame_ptr& p_frame, std::size_t& count, point_type& point, socket_ptr& p_socket, context_ptr& p_context){
    info_param_ptr p_param = std::make_shared<info_param>();
    p_param->p_frame = std::make_shared<frame_ptr::element_type>(p_frame->begin(), p_frame->begin() + count);
    if(!mp_protocol->decode(p_param, p_param->p_frame)){
        return;
    }
    info_net_proxy_ptr p_proxy;
    auto iter = m_proxys.find(p_param->address);
    if(m_proxys.end() == iter){
        p_proxy = std::make_shared<info_net_proxy>();
        p_proxy->p_context = p_context;
        p_proxy->p_socket = p_socket;
        p_proxy->point = point;
        m_proxys.insert(std::make_pair(p_param->address, p_proxy));
    }else{
        p_proxy = iter->second;
        if(p_proxy->point != point){
            LOG_WARN("源端端点改变; SIP地址"<<p_param->address<<"; 旧端点:"<<p_proxy->point.address().to_string()<<"; 新端点:"<<point.address().to_string());
            p_proxy->point = point;
        }
    }
    
    notify(p_proxy);
}

int state_machine::notify(info_net_proxy_ptr p_info){
    while(!p_info->params.empty()){
        auto p_param = *p_info->params.begin();
        p_info->params.erase(p_info->params.begin());

        if(ACTION_REGISTER == p_param->action && "1" == p_param->params[PARAM_CSEQ_INDEX]){
            p_info->status = STATUS_REGISTER_1;
            auto p_response = std::make_shared<info_param>();
            // 保存请求的参数
            p_response->params.swap(p_param->params);
            // 回应的To@sip是请求的From@sip，另外回应的From@tag为请求的From@tag
            p_response->params[PARAM_TO_SIP].swap(p_response->params[PARAM_FROM_SIP]);

            // Via@address需要设置成本地IP和端口
            auto local_point = p_info->p_socket->local_endpoint().address();
            p_response->params[PARAM_VIA_ADDRESS] = (boost::format("%s:%d") % p_info->p_socket->local_endpoint().address().to_string() % p_info->p_socket->local_endpoint().port()).str();
            
            // WWW-Authenticate realm取项目编号，nonce取随机数
            p_response->params[PARAM_WWW_AUTHENTICATE] = (boost::format("Digest realm=\"%s\", nonce=\"%s\"")
                % m_realm % mp_protocol->random_str()).str();
            
            p_response->params[PARAM_CONTENT_LENGTH] = "0";

            p_response->action = ACTION_UNAUTHORIZED;
            p_response->code = 401;

            if(!mp_protocol->encode(p_response->p_frame, p_response)){
                continue;
            }
            send_frame(p_response->p_frame, p_info);
        }else if(ACTION_REGISTER == p_param->action  && "2" == p_param->params[PARAM_CSEQ_INDEX] && STATUS_REGISTER_1 == p_info->status){
            p_info->status = STATUS_REGISTER_3;
            auto p_response = std::make_shared<info_param>();
            // 保存请求的参数
            p_response->params.swap(p_param->params);
            // 回应的To@sip是请求的From@sip，另外回应的From@tag为请求的From@tag
            p_response->params[PARAM_TO_SIP].swap(p_response->params[PARAM_FROM_SIP]);

            // Via@address需要设置成本地IP和端口
            auto local_point = p_info->p_socket->local_endpoint().address();
            p_response->params[PARAM_VIA_ADDRESS] = (boost::format("%s:%d") % p_info->p_socket->local_endpoint().address().to_string() % p_info->p_socket->local_endpoint().port()).str();

            p_response->params[PARAM_DATE] = ptime_to_param_date(boost::posix_time::second_clock::local_time());
            
            // WWW-Authenticate realm取项目编号，nonce取随机数
            p_response->params[PARAM_WWW_AUTHENTICATE] = (boost::format("Digest realm=\"%s\", nonce=\"%s\"")
                % m_realm % mp_protocol->random_str()).str();

            p_response->params[PARAM_CONTENT_LENGTH] = "0";

            p_response->action = ACTION_UNAUTHORIZED;
            p_response->code = 401;
            

            if(!mp_protocol->encode(p_response->p_frame, p_response)){
                continue;
            }
            send_frame(p_response->p_frame, p_info);
        }
    }
    
    return 0;
}

int state_machine::send_frame(frame_ptr p_frame, info_net_proxy_ptr p_info){
    LOG_INFO("发送数据:"<<frame_to_str(p_frame));
    p_info->p_socket->async_send_to(boost::asio::buffer(*p_frame, p_frame->size()), p_info->point, [p_frame](const boost::system::error_code& e, const std::size_t& ){
        if(e){
            LOG_ERROR("发送数据时发生错误:"<<e.message());
        }
    });
    return ES_SUCCESS;
}

std::string state_machine::ptime_to_param_date(const boost::posix_time::ptime& time){
    if(time.is_not_a_date_time()){
        return "";
    }
    try
    {
        return boost::posix_time::to_simple_string(time);
    }
    catch(const std::exception&)
    {
    }
    return "";
}