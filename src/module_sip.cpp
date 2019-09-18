#include "module_sip.h"
#include "utility_tool.h"
#include "error_code.h"
#include <boost/format.hpp>


#define LINE_END "\r\n"

#define SIP_VERSION_2_0 "SIP/2.0"

#define ALGORITHM_MD5 "MD5"

#define ACTION_REGISTER "REGISTER"
#define ACTION_OK "OK"
#define ACTION_UNAUTHORIZED "Unauthorized"
#define ACTION_MESSAGE "MESSAGE"
#define ACTION_INVITE "INVITE"

#define STATUS_MAKE(ACTION,INDEX) ACTION#INDEX
#define STATUS_REGISTER_ "REGISTER_"
#define STATUS_INVITE_ "INVITE_"

module_sip::module_sip()
{

}


bool module_sip::get_transaction_id(std::string& id, info_param_ptr p_param){
    std::string branch, method;
    if(!get_value(branch, p_param->via, ';', "branch") || !get_value(method, p_param->cseq, ' ', 1)){
        return false;
    }
    id = branch + "@" + method;
    return true;
}

bool module_sip::split(std::vector<std::string>& params, const std::string& data, const char s){
    params.clear();
    std::size_t pos_start = 0;
    for(std::size_t pos_end = 0; pos_end < data.size(); ++pos_end){
        if(s == data[pos_end]){
            params.push_back(data.substr(pos_start, pos_end - pos_start));
            pos_start = pos_end + 1;
        }
    }
    if(pos_start < data.size()){
        params.push_back(data.substr(pos_start));
    }
    return true;
}

bool module_sip::get_value(std::string& v, const std::string& data, const char s, const std::string& k){
    std::vector<std::string> params, kv;
    split(params, data, s);
    for(auto& p : params){
        split(kv, p, '=');
        if(2 != kv.size() || k != kv[0]){
            continue;
        }
        v = kv[1];
        return true;
    }
    return false;
}

bool module_sip::get_value(std::string& v, const std::string& data, const char s, const std::size_t index){
    std::vector<std::string> params;
    split(params, data, s);
    if(index >= params.size()){
        return false;
    }
    v = params[index];
    return true;
}

void module_sip::remove_char(std::string& v, const char s){
    std::size_t i = 0;
    for(i = 0; i < v.size(); ++i){
        if(s != v[i]){
            v.erase(0, i);
            break;
        }
    }
    if(i >= v.size()){
        // 数据都为s
        v.clear();
        return;
    }
    std::size_t pos_end = v.size() - 1;
    for(; pos_end > 0; --pos_end){
        if(s != v[pos_end]){
            v.erase(pos_end, v.size() - pos_end - 1);
            return;
        }
    }
    if(0 == pos_end){
        // 只有一个非s字符
        v.erase(1, v.size() - 1);
    }
}

int module_sip::do_register(info_param_ptr p_param, info_transaction_ptr p_transaction){
    std::string action;
    if(!get_value(action, p_param->header, ' ', 0)){
        return MD_UNKNOW;
    }
    if(ACTION_REGISTER == action && p_transaction->status.empty()){
        // 初始状态
        p_transaction->status = STATUS_MAKE(STATUS_REGISTER_,1);
        auto p_response = create_response_by_request(401, ACTION_UNAUTHORIZED, p_param);
        auto p_buffer = create_buffer_from_response(p_response);
        send_frame(p_buffer, p_param);
    }else if(ACTION_REGISTER == action && STATUS_MAKE(STATUS_REGISTER_,1) == p_transaction->status){
        p_transaction->status = STATUS_MAKE(STATUS_REGISTER_,3);
        auto p_response = create_response_by_request(200, ACTION_OK, p_param);
        p_response->date = ptime_to_register_date(boost::posix_time::second_clock::local_time());
        auto p_buffer = create_buffer_from_response(p_response);
        send_frame(p_buffer, p_param);
    }else{
        LOG_WARN("无法处理的请求:"<<p_param->header);
        return MD_UNKNOW;
    }
    return MD_SUCCESS;
}

info_param_ptr module_sip::create_response_by_request(const int& code, const std::string& action, info_param_ptr p_request){
    std::string data;
    auto p_response = std::make_shared<info_param_ptr::element_type>();
    p_response->header = (boost::format("%s %d %s") % SIP_VERSION_2_0 % code % action).str();

    /*
    if(get_value(data, p_request->contact, ';', 0)){
        p_response->to = data;
    }else{
        if(get_value(data, p_request->from, ';', 0)){
            p_response->to = data;
        }else{
            LOG_ERROR("找不到域[From]:"<<p_request->from);
            return info_param_ptr();
        }
    }
    */
    if(get_value(data, p_request->from, ';', 0)){
        p_response->to = data;
    }else{
        LOG_ERROR("找不到域[From]:"<<p_request->from);
        return info_param_ptr();
    }

    if(get_value(data, p_request->to, ';', 0)){
        p_response->from = data;
    }else{
        LOG_ERROR("找不到域[To]:"<<p_request->to);
        return info_param_ptr();
    }
    if(get_value(data, p_request->from, ';', "tag")){
        p_response->from = p_response->from + ";" + data;
    }else{
        LOG_ERROR("找不到域[From.tag]:"<<p_request->from);
        return info_param_ptr();
    }

    std::vector<std::string> params, sub_params, kv;
    split(params, p_request->via, ' ');
    if(2 > params.size()){
        LOG_ERROR("域[Via]非法:"<<p_request->via);
        return info_param_ptr();
    }
    split(sub_params, params[1], ';');
    data.clear();
    // 直接取socket的本地地址，可能会取到0.0.0.0
    auto ip = p_request->p_socket->local_endpoint().address().to_string();
    if("0.0.0.0" == ip || "127.0.0.1" == ip){

    }
    std::string  address = (boost::format("%s:%d") % p_request->p_socket->local_endpoint().address().to_string() % p_request->p_socket->local_endpoint().port()).str();
    for(auto& d : sub_params){
        split(kv, d, '=');
        if(1 == kv.size()){
            if("report" == d){
                if(data.empty()){
                    data = (boost::format("%s=%d") % d % p_request->p_socket->local_endpoint().port()).str();
                }else{
                    data = (boost::format(";%s=%d") % d % p_request->p_socket->local_endpoint().port()).str();
                }
            }else{
                if(data.empty()){
                    data = (boost::format("%s") % d).str();
                }else{
                    data = (boost::format(";%s") % d).str();
                }
            }
        }else if(2 == kv.size()){
            if(data.empty()){
                data = (boost::format("%s") % d).str();
            }else{
                data = (boost::format(";%s") % d).str();
            }
        }else{
            LOG_ERROR("域[Via]属性非法:"<<d);
            return info_param_ptr();
        }
    }
    // 增加received，取远端端点
    if(data.empty()){
        data = (boost::format("%s=%s:%d") % "received" % p_request->p_socket->local_endpoint().address().to_string() % p_request->p_socket->local_endpoint().port()).str();
    }else{
        data = (boost::format(";%s=%s:%d") % "received" % p_request->p_socket->local_endpoint().address().to_string()  % p_request->p_socket->local_endpoint().port()).str();
    }

    p_response->cseq = p_request->cseq;
    p_response->call_id = p_request->call_id;
    p_response->max_forwards = "70";
    p_response->expires = "3600";
    return p_response;
}

std::shared_ptr<std::string> module_sip::create_buffer_from_response(info_param_ptr p_response){
    auto p_buffer = std::make_shared<std::string>();
    std::stringstream stream;
    stream<<p_response->header<<LINE_END;
    stream<<"To: "<<p_response->to<<LINE_END;
    stream<<"From: "<<p_response->from<<LINE_END;
    stream<<"Via: "<<p_response->via<<LINE_END;
    stream<<"CSeq: "<<p_response->cseq<<LINE_END;
    stream<<"Call-ID: "<<p_response->call_id<<LINE_END;
    stream<<"Max-Forwards: "<<p_response->max_forwards<<LINE_END;
    stream<<"Expires: "<<p_response->expires<<LINE_END;

    if(!p_response->date.empty()){
        stream<<"Date: "<<p_response->date<<LINE_END;
    }
    stream<<LINE_END;
    *p_buffer = stream.str();
    return p_buffer;
}

int module_sip::send_frame(std::shared_ptr<std::string> p_buffer, info_param_ptr p_param){
    LOG_INFO("发送数据:"<<*p_buffer);
    p_param->p_socket->async_send_to(boost::asio::buffer(p_buffer->c_str(), p_buffer->size()), p_param->point, [p_buffer, p_param](const boost::system::error_code& e, const std::size_t& ){
        if(e){
            LOG_ERROR("发送数据时发生错误:"<<e.message());
        }
    });
    return MD_SUCCESS;
}

std::string module_sip::ptime_to_register_date(const boost::posix_time::ptime& time){
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

int module_sip::do_invite(info_param_ptr p_param, info_transaction_ptr p_transaction){
    std::string action;
    if(!get_value(action, p_param->header, ' ', 0)){
        return MD_UNKNOW;
    }
    if(ACTION_INVITE == action && p_transaction->status.empty()){
        p_transaction->status = STATUS_MAKE(STATUS_INVITE_,1);

        auto p_server_media = find_server_by_type(SERVER_TYPE_MEDIA);
        auto p_request = std::make_shared<info_param_ptr::element_type>();
        p_request->to =
    }
    return MD_SUCCESS;
}

bool module_sip::add_server(const std::string& number, socket_ptr p_socket, point_type point, const std::string& type){
    auto iter = m_servers.find(number);
    if(m_servers.end() == iter){
        auto  p_server = std::make_shared<info_server_ptr::element_type>();
        p_server->p_socket = p_socket;
        p_server->point = point;
        p_server->number = number;
        p_server->type = type;
        m_servers.insert(std::make_pair(p_server->number, p_server));
    }else{
        auto p_server = iter->second;
        p_server->p_socket = p_socket;
        p_server->point = point;
        p_server->type = type;
    }
    return true;
}

info_server_ptr module_sip::find_server_by_number(const std::string& number){
    auto iter = m_servers.find(number);
    if(m_servers.end() == iter){
        return info_server_ptr();
    }
    return iter->second;
}

info_server_ptr module_sip::find_server_by_type(const std::string& type){
    for(auto& kv : m_servers){
        if(kv.second->type == type){
            return kv.second;
        }
    }
    return info_server_ptr();
}
