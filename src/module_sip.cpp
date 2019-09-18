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
#define ACTION_ACK "ACK"
#define ACTION_BYE "BYE"

#define STATUS_MAKE(ACTION,INDEX) ACTION#INDEX
#define STATUS_REGISTER_ "REGISTER_"
#define STATUS_INVITE_ "INVITE_"


#define PARAM_VIA "Via"
#define PARAM_FROM "From"
#define PARAM_TO "To"
#define PARAM_WWW_AUTHENTICATE "WWW-Authenticate"
#define PARAM_CSEQ "CSeq"
#define PARAM_AUTHORIZATION "Authorization"
#define PARAM_DATE "Date"
#define PARAM_CALL_ID "Call-ID"
#define PARAM_CONTACT "Contact"
#define PARAM_MAX_FORWARDS "Max-Forwards"
#define PARAM_EXPIRES "Expires"
#define PARAM_CONTENT_LENGTH "Content-Length"
#define PARAM_CONTENT_TYPE "Content-Type"
#define PARAM_SUBJECT "Subject"

#define CONTENT_TYPE_XML "Application/MANSCDP+xml"
#define CONTENT_TYPE_SDP "Application/SDP"

#define MESSAGE_NOTIFY_CMD_TYPE "Notify.CmdType"
#define MESSAGE_KEEPALIVE "Keepalive"

module_sip::~module_sip()
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

        // WWW-Authenticate realm取项目编号，nonce取随机数
        p_response->www_authenticate = (boost::format("WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\"") % m_realm % random_once()).str();

        auto p_buffer = create_buffer(p_response);
        p_transaction->ptimer->send_buffer(p_buffer, p_param->point, p_param->p_socket);
    }else if(ACTION_REGISTER == action && STATUS_MAKE(STATUS_REGISTER_,1) == p_transaction->status){
        p_transaction->status = STATUS_END;
        auto p_response = create_response_by_request(200, ACTION_OK, p_param);
        p_response->date = ptime_to_register_date(boost::posix_time::second_clock::local_time());
        auto p_buffer = create_buffer(p_response);
        p_transaction->ptimer->send_buffer(p_buffer, p_param->point, p_param->p_socket);
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

std::shared_ptr<std::string> module_sip::create_buffer(info_param_ptr p_response){
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

int module_sip::send_buffer(std::shared_ptr<std::string> p_buffer, point_type point, socket_ptr p_socket){
    LOG_INFO("发送数据:"<<*p_buffer);
    p_socket->async_send_to(boost::asio::buffer(p_buffer->c_str(), p_buffer->size()), point, [p_buffer, point, p_socket](const boost::system::error_code& e, const std::size_t& ){
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
        p_transaction->params.insert(std::make_pair(p_transaction->status, p_param));

        auto p_server_media = find_server_by_type(SERVER_TYPE_MEDIA);
        auto p_server_sip = find_server_by_type(SERVER_TYPE_SIP);
        auto p_request = create_request_by_request(p_param, ACTION_INVITE, p_server_sip, p_server_media);
        if(!p_request){
            return MD_UNKNOW;
        }
        auto p_buffer = create_buffer(p_request);
        p_transaction->ptimer->send_buffer(p_buffer, p_server_media->point, p_server_sip->p_socket);
    }else if(STATUS_MAKE(STATUS_INVITE_,1) == p_transaction->status && is_confirm(200, ACTION_OK, p_param)){
        auto status_old = p_transaction->status;
        p_transaction->status = STATUS_MAKE(STATUS_INVITE_,3);
        auto iter = p_transaction->params.find(status_old);
        if(p_transaction->params.end() == iter){
            LOG_ERROR("内部错误，找不到对应的请求:"<<status_old);
            return MD_UNKNOW;
        }
        auto prequest_old = iter->second;
        if(!is_response(p_param,prequest_old)){
            LOG_WARN("不是对应的请求，将被抛弃");
            return MD_UNKNOW;
        }
        if(CONTENT_TYPE_SDP != p_param->content_type){
            LOG_WARN("回应的内容类型不为SDP:"<<p_param->content_type);
            return MD_SDP;
        }

        // 发送SDP内容给设备，以便设备和媒体服务器能进行RTP传输
        // 设备编码在步骤1的Subject中
        std::vector<std::string> param1, param2;
        if(!split(param1, prequest_old->subject, ',') || 2 != param1.size() || !split(param2, param1[1], ':') || 2 != param2.size()){
            LOG_ERROR("无法从[Subject]中解析出目标设备编码:"<<prequest_old->subject);
            return MD_SUBJECT;
        }
        auto p_device = find_server_by_number(param2[1]);
        if(!p_device){
            LOG_ERROR("获取设备信息失败；设备编码:"<<param2[1]);
            return MD_NUMBER;
        }
        auto p_server_sip = find_server_by_type(SERVER_TYPE_SIP);
        auto p_request = create_request_by_request(p_param, ACTION_INVITE, p_server_sip, p_device);
        if(!p_request){
            return MD_UNKNOW;
        }
        auto p_buffer = create_buffer(p_request);
        p_transaction->ptimer->send_buffer(p_buffer, p_device->point, p_server_sip->p_socket);
    }else if(STATUS_MAKE(STATUS_INVITE_,3) == p_transaction->status && is_confirm(200, ACTION_OK, p_param)){
        auto status_old = p_transaction->status;
        p_transaction->status = STATUS_MAKE(STATUS_INVITE_,5);
        auto iter = p_transaction->params.find(status_old);
        if(p_transaction->params.end() == iter){
            LOG_ERROR("内部错误，找不到对应的请求:"<<status_old);
            return MD_UNKNOW;
        }
        auto prequest_old = iter->second;
        if(!is_response(p_param,prequest_old)){
            LOG_WARN("不是对应的请求，将被抛弃");
            return MD_UNKNOW;
        }
        if(CONTENT_TYPE_SDP != p_param->content_type){
            LOG_WARN("回应的内容类型不为SDP:"<<p_param->content_type);
            return MD_SDP;
        }

        // 发送SDP内容给媒体服务器
        auto p_server_media = find_server_by_type(SERVER_TYPE_MEDIA);
        auto p_server_sip = find_server_by_type(SERVER_TYPE_SIP);
        auto presponse_media = create_request_by_request(p_param, ACTION_INVITE, p_server_sip, p_server_media);
        if(!presponse_media){
            return MD_UNKNOW;
        }
        p_transaction->ptimer->send_buffer(create_buffer(presponse_media), p_server_media->point, p_server_sip->p_socket);

        // 发送ACK给设备
        auto number_old = get_number(prequest_old->from);
        auto p_device = find_server_by_number(number_old);
        if(!p_device){
            LOG_ERROR("获取设备信息失败；设备编码:"<<number_old);
            return MD_NUMBER;
        }
        auto presponse_device = create_request_by_request(prequest_old, ACTION_INVITE, p_server_sip, p_device);
        if(!presponse_device){
            return MD_UNKNOW;
        }
        // ACK不带SDP内容
        presponse_device->content_type.clear();
        presponse_device->content.clear();
        p_transaction->ptimer->send_buffer(create_buffer(presponse_device), p_device->point, p_server_sip->p_socket);

        // 将客户端的SDP发给媒体服务器，以便客户端和媒体服务器能传输RTP
        p_transaction->status = STATUS_MAKE(STATUS_INVITE_,7);
        iter = p_transaction->params.find(STATUS_MAKE(STATUS_INVITE_,1));
        if(p_transaction->params.end() == iter){
            LOG_ERROR("内部错误，找不到客户端的请求:"<<STATUS_MAKE(STATUS_INVITE_,1));
            return MD_UNKNOW;
        }
        auto prequest_client = iter->second;
        auto prequest_client_to_media = create_request_by_request(prequest_client, ACTION_INVITE, p_server_sip, p_server_media);
        if(!presponse_media){
            return MD_UNKNOW;
        }
        p_transaction->ptimer->send_buffer(create_buffer(prequest_client_to_media), p_server_media->point, p_server_sip->p_socket);
    }else if(STATUS_MAKE(STATUS_INVITE_,7) == p_transaction->status && is_confirm(200, ACTION_OK, p_param)){
        auto status_old = p_transaction->status;
        p_transaction->status = STATUS_MAKE(STATUS_INVITE_,9);
        auto iter = p_transaction->params.find(status_old);
        if(p_transaction->params.end() == iter){
            LOG_ERROR("内部错误，找不到对应的请求:"<<status_old);
            return MD_UNKNOW;
        }
        auto prequest_old = iter->second;
        if(!is_response(p_param,prequest_old)){
            LOG_WARN("不是对应的请求，将被抛弃");
            return MD_UNKNOW;
        }
        if(CONTENT_TYPE_SDP != p_param->content_type){
            LOG_WARN("回应的内容类型不为SDP:"<<p_param->content_type);
            return MD_SDP;
        }

        // 发送SDP内容给客户端，以便客户端和媒体服务器能进行RTP传输
        iter = p_transaction->params.find(STATUS_MAKE(STATUS_INVITE_,1));
        if(p_transaction->params.end() == iter){
            LOG_ERROR("内部错误，找不到客户端的请求:"<<STATUS_MAKE(STATUS_INVITE_,1));
            return MD_UNKNOW;
        }
        auto number_client = get_number(iter->second->from);
        auto p_client = find_server_by_number(number_client);
        if(!p_client){
            LOG_ERROR("获取客户端信息失败；设备编码:"<<number_client);
            return MD_NUMBER;
        }
        auto p_server_sip = find_server_by_type(SERVER_TYPE_SIP);
        auto presponse_client = create_response_by_request(200, ACTION_OK, p_param);
        if(!presponse_client){
            return MD_UNKNOW;
        }
        p_transaction->ptimer->send_buffer(create_buffer(presponse_client), p_client->point, p_server_sip->p_socket);
    }else if(STATUS_MAKE(STATUS_INVITE_,9) == p_transaction->status && ACTION_ACK == action){
        auto status_old = p_transaction->status;
        p_transaction->status = STATUS_MAKE(STATUS_INVITE_,11);
        auto iter = p_transaction->params.find(status_old);
        if(p_transaction->params.end() == iter){
            LOG_ERROR("内部错误，找不到对应的请求:"<<status_old);
            return MD_UNKNOW;
        }
        auto prequest_old = iter->second;
        if(!is_response(p_param,prequest_old)){
            LOG_WARN("不是对应的请求，将被抛弃");
            return MD_UNKNOW;
        }

        // 发送ACK给媒体服务器
        auto p_server_sip = find_server_by_type(SERVER_TYPE_SIP);
        auto p_server_media = find_server_by_type(SERVER_TYPE_MEDIA);
        auto prequest = create_request_by_request(p_param, ACTION_ACK, p_server_sip, p_server_media);
        if(!prequest){
            return MD_UNKNOW;
        }
        p_transaction->ptimer->send_buffer(create_buffer(prequest), p_server_media->point, p_server_sip->p_socket);
    }else if(STATUS_MAKE(STATUS_INVITE_,11) == p_transaction->status && ACTION_BYE == action){
        p_transaction->status = STATUS_MAKE(STATUS_INVITE_,13);

        // 发送OK给客户端
        auto number_client = get_number(p_param->from);
        auto p_client = find_server_by_number(number_client);
        if(!p_client){
            LOG_ERROR("获取客户端信息失败；设备编码:"<<number_client);
            return MD_NUMBER;
        }
        auto p_server_sip = find_server_by_type(SERVER_TYPE_SIP);
        auto presponse = create_response_by_request(200, ACTION_OK, p_param);
        if(!presponse){
            return MD_UNKNOW;
        }
        p_transaction->ptimer->send_buffer(create_buffer(presponse), p_client->point, p_server_sip->p_socket);

        // 发送BYTE给媒体服务器
        auto p_server_media = find_server_by_type(SERVER_TYPE_MEDIA);
        auto prequest = create_request_by_request(p_param, ACTION_BYE, p_server_sip, p_server_media);
        if(!prequest){
            return MD_UNKNOW;
        }
        p_transaction->ptimer->send_buffer(create_buffer(prequest), p_server_media->point, p_server_sip->p_socket);
    }else if(STATUS_MAKE(STATUS_INVITE_,13) == p_transaction->status && is_confirm(200, ACTION_OK, p_param)){
        p_transaction->status = STATUS_MAKE(STATUS_INVITE_,16);

        // 发送BYTE给媒体服务器
        auto p_server_sip = find_server_by_type(SERVER_TYPE_SIP);
        auto p_server_media = find_server_by_type(SERVER_TYPE_MEDIA);
        auto prequest = create_request_by_request(p_param, ACTION_BYE, p_server_sip, p_server_media);
        if(!prequest){
            return MD_UNKNOW;
        }
        p_transaction->ptimer->send_buffer(create_buffer(prequest), p_server_media->point, p_server_sip->p_socket);
    }else if(STATUS_MAKE(STATUS_INVITE_,16) == p_transaction->status && is_confirm(200, ACTION_OK, p_param)){
        p_transaction->status = STATUS_MAKE(STATUS_INVITE_,18);

        // 发送BYTE给设备
        auto p_server_sip = find_server_by_type(SERVER_TYPE_SIP);
        // 设备编码在步骤1的Subject中
        auto iter = p_transaction->params.find(STATUS_MAKE(STATUS_INVITE_,1));
        if(p_transaction->params.end() == iter){
            LOG_ERROR("内部错误，找不到对应的请求:"<<STATUS_MAKE(STATUS_INVITE_,1));
            return MD_UNKNOW;
        }
        std::vector<std::string> param1, param2;
        if(!split(param1, iter->second->subject, ',') || 2 != param1.size() || !split(param2, param1[1], ':') || 2 != param2.size()){
            LOG_ERROR("无法从[Subject]中解析出目标设备编码:"<<iter->second->subject);
            return MD_SUBJECT;
        }
        auto p_device = find_server_by_number(param2[1]);
        if(!p_device){
            LOG_ERROR("获取设备信息失败；设备编码:"<<param2[1]);
            return MD_NUMBER;
        }
        auto prequest = create_request_by_request(p_param, ACTION_BYE, p_server_sip, p_device);
        if(!prequest){
            return MD_UNKNOW;
        }
        p_transaction->ptimer->send_buffer(create_buffer(prequest), p_device->point, p_server_sip->p_socket);
    }else if(STATUS_MAKE(STATUS_INVITE_,18) == p_transaction->status && is_confirm(200, ACTION_OK, p_param)){
        // 事务结束
        p_transaction->status = STATUS_END;
    }
    return MD_SUCCESS;
}

std::string module_sip::get_number(const std::string& v){
    std::size_t pos_start = 0, pos_end = 0;
    if(std::string::npos == (pos_start = v.find("sip:")) || std::string::npos == (pos_end = v.find("@", pos_start))){
        LOG_ERROR("获取number失败:"<<v);
        return "";
    }
    return v.substr(pos_start + 4, pos_end - pos_start - 4);
}

bool module_sip::is_confirm(const int& code, const std::string& action, info_param_ptr p_param){
    std::vector<std::string> params;
    if(!split(params, p_param->header, ' ') || 3 != params.size()){
        return false;
    }
    if(SIP_VERSION_2_0 != params[0]){
        return false;
    }
    if(action != params[2]){
        return false;
    }
    if(code != atoi(params[1].c_str())){
        return false;
    }
    return true;
}

bool module_sip::is_response(info_param_ptr presponse, info_param_ptr prequest){
    // 根据Call-ID、CSeq、和From.tag判断是不是对应的回应
    if(presponse->call_id != prequest->call_id || presponse->cseq != prequest->cseq){
        return false;
    }
    std::string tag_response, tag_request;
    if(!get_value(tag_response, presponse->from, ';', "tag") || !get_value(tag_request, prequest->from, ';', "tag") || tag_response != tag_request){
        return false;
    }
    return true;
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

info_param_ptr module_sip::create_request_by_request(info_param_ptr prequest_old, const std::string& action, info_server_ptr pserver_src, info_server_ptr pserver_desc){
    auto prequest_new = std::make_shared<info_param_ptr::element_type>();
    std::string data;
    prequest_new->header = (boost::format("%s %s@%s:%d %s") % action % pserver_desc->number % pserver_desc->point.address().to_string() % pserver_desc->point.port() % SIP_VERSION_2_0).str();
    prequest_new->to = (boost::format("<sip:%s@%s:%d>") % pserver_desc->number % pserver_desc->point.address().to_string() % pserver_desc->point.port()).str();
    prequest_new->from = (boost::format("<sip:%s@%s:%d>;tag=%s") % pserver_src->number % pserver_src->point.address().to_string() % pserver_src->point.port()
                          % random_tag()).str();

    // Via: SIP/2.0/UDP 192.168.2.64:5060;rport;branch=z9hG4bK1192549781
    std::vector<std::string> params, sub_params, kv;
    split(params, prequest_old->via, ' ');
    if(2 > params.size()){
        LOG_ERROR("域[Via]非法:"<<prequest_old->via);
        return info_param_ptr();
    }
    split(sub_params, params[1], ';');
    data.clear();
    if(1 >= sub_params.size()){
        data = params[1];
    }else{
        // 只需要修改第一个参数
        data = (boost::format("%s:%d") % pserver_src->point.address().to_string() % pserver_src->point.port()).str();
        for(auto iter = sub_params.begin() + 1; iter != sub_params.end(); ++iter){
            data = data + ";" + *iter;
        }
    }
    prequest_new->via = (boost::format("%s %s") % params[0] % data).str();
    prequest_new->subject = prequest_old->subject;
    prequest_new->cseq = prequest_old->cseq;
    prequest_new->call_id = prequest_old->call_id;
    prequest_new->content_type = prequest_old->content_type;
    prequest_new->content = prequest_old->content;
    prequest_new->max_forwards = "70";
    prequest_new->expires = "3600";
    return prequest_new;
}

std::string module_sip::random_tag(){
    return "1223";
}

int module_sip::decode(info_param_ptr &p_param, frame_ptr &p_frame)
{
    if (!p_param)
    {
        p_param = std::make_shared<info_param>();
    }
    const char *p_data = reinterpret_cast<const char *>(p_frame->data());
    auto p_start = p_data;
    auto p_end = p_start + p_frame->size();
    bool flag_cmd_init = false;
    auto p_line_start = p_start, p_line_end = p_end, p_param_start = p_start, p_param_end = p_end;

    while (true)
    {
        if(4 <= (p_end - p_start) && 0 == memcmp(p_start, "\r\n\r\n", 4)){
            //是分隔符
            p_start += 4;
            break;
        }
        if (!find_line(&p_line_start, &p_line_end, &p_start, p_end))
        {
            break;
        }
        if (p_line_start == p_line_end)
        {
            break;
        }
        if (!flag_cmd_init)
        {
            std::vector<const char*> ps;
            while(true){
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
                {
                    break;
                }
                ps.push_back(p_param_start);
                ps.push_back(p_param_end);
            }
            // 头部由3部分组成，第一个或第三个参数为SIP_VERSION_2_0
            if(6 != ps.size() || (0 != strcmp(SIP_VERSION_2_0, ps[0]) && 0 != strcmp(SIP_VERSION_2_0, ps[4]))){
                break;
            }
            flag_cmd_init = true;
            p_param->header = std::string(p_line_start, p_line_start);
        }
        else
        {
            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ':'))
            {
                LOG_ERROR("找不到键值对分隔符:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                return false;
            }
            remove_char(&p_param_start, &p_param_end, ' ');
            remove_char(&p_line_start, &p_line_end, ' ');
            std::string name(p_param_start, p_param_end);
            if (0 == strcmp(PARAM_VIA, p_param_start))
            {
                p_param->via = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_FROM, p_param_start))
            {
               p_param->from = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_TO, p_param_start))
            {
               p_param->to = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_CSEQ, p_param_start))
            {
               p_param->cseq = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_AUTHORIZATION, p_param_start))
            {
               p_param->authorization = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_CONTACT, p_param_start))
            {
                p_param->contact = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_WWW_AUTHENTICATE, p_param_start))
            {
               p_param->www_authenticate = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_DATE, p_param_start))
            {
                p_param->date = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_CALL_ID, p_param_start))
            {
                p_param->call_id = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_MAX_FORWARDS, p_param_start))
            {
                p_param->max_forwards = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_EXPIRES, p_param_start))
            {
                p_param->expires = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_SUBJECT, p_param_start))
            {
                p_param->subject = std::string(p_line_start, p_line_end);
            }else if (0 == strcmp(PARAM_CONTENT_TYPE, p_param_start))
            {
                p_param->content_type = std::string(p_line_start, p_line_end);
            }else{
            }
        }
    }

    // 看是不是有数据体需要解析
    if(!p_param->content_type.empty() && 0 < (p_end - p_start)){
        p_param->content = std::string(p_start, p_end);
    }
    return MD_SUCCESS;
}

bool module_sip::find_line(const char **pp_line_start, const char **pp_line_end, const char **pp_start, const char *p_end)
{
    if (nullptr == pp_line_start || nullptr == pp_line_end || nullptr == pp_start || nullptr == p_end)
    {
        return false;
    }
    *pp_line_start = *pp_start;
    for (auto p = *pp_line_start; p < p_end; ++p)
    {
        if ('\n' == *p)
        {
            if (p > *pp_line_start && '\r' == *(p - 1))
            {
                *pp_line_end = p - 1;
            }
            else
            {
                *pp_line_end = p;
            }
            *pp_start = p + 1;
            return true;
        }
    }
    if (*pp_start < p_end)
    {
        *pp_line_start = *pp_start;
        *pp_line_end = p_end;
        if ('\n' == *(*pp_line_end - 1))
        {
            --(*pp_line_end);
        }
        if (*pp_line_start < *pp_line_end && '\r' == *(*pp_line_end - 1))
        {
            --(*pp_line_end);
        }
        return true;
    }
    return false;
}

bool module_sip::find_param(const char **pp_param_start, const char **pp_param_end, const char **pp_start, const char *p_end, const char s)
{
    if (nullptr == pp_param_start || nullptr == pp_param_end || nullptr == pp_start || nullptr == p_end)
    {
        return false;
    }
    *pp_param_start = *pp_start;
    for (auto p = *pp_param_start; p < p_end; ++p)
    {
        if (*p == s)
        {
            *pp_param_end = p;
            *pp_start = p + 1;
            return true;
        }
    }
    if (*pp_start < p_end)
    {
        *pp_param_start = *pp_start;
        *pp_param_end = p_end;
        *pp_start = p_end;
        return true;
    }
    return false;
}

bool module_sip::remove_char(const char **pp_start, const char **pp_end, const char s)
{
    if (nullptr == pp_start || nullptr == pp_end)
    {
        return false;
    }
    if (*pp_start == *pp_end)
    {
        return true;
    }
    for (auto p = *pp_start; p < *pp_end; ++p)
    {
        if (s != *p)
        {
            *pp_start = p;
            break;
        }
    }
    for (auto p = *pp_end - 1; p >= *pp_start; --p)
    {
        if (s != *p)
        {
            *pp_end = p + 1;
            break;
        }
    }
    return true;
}

void module_sip::do_work(info_param_ptr p_param, info_transaction_ptr p_transaction){
    if(!p_transaction->fun_work){
        // 根据业务选择不同的业务处理函数
        std::string action;
        if(!get_value(action, p_param->header, ' ', 0)){
            LOG_ERROR("非开始信息头，将被丢弃:"<<p_param->header);
            return;
        }
        if("REGISTER" == action){
            p_transaction->fun_work = std::bind(&module_sip::do_register, shared_from_this(), std::placeholders::_1, std::placeholders::_2);
        }else if("MESSAGE" == action){
            if(CONTENT_TYPE_XML != p_param->content_type){
                LOG_ERROR("无法处理的消息内容格式:"<<p_param->content_type);
                return;
            }
            tinyxml2::XMLDocument doc;
            try{
                doc.Parse(p_param->content.c_str());
            }catch(const std::exception& e){
                LOG_ERROR("解析XML数据时发生错误:"<<e.what());
                return ;
            }
            auto pnode_root = doc.RootElement();
            std::string data;
            if(nullptr == pnode_root || !find_node_value(data, MESSAGE_NOTIFY_CMD_TYPE, pnode_root)){
                LOG_ERROR("找不到消息命令类型");
                return;
            }
            if(MESSAGE_KEEPALIVE == data){
                p_transaction->fun_work = std::bind(&module_sip::do_message_keepalive, shared_from_this(), std::placeholders::_1, std::placeholders::_2);
            }else{
                LOG_ERROR("无法处理的消息命令类型:"<<data);
                return;
            }
        }else if("INVITE" == action){
            p_transaction->fun_work = std::bind(&module_sip::do_invite, shared_from_this(), std::placeholders::_1, std::placeholders::_2);
        }else{
            LOG_ERROR("无法处理的信息头:"<<p_param->header);
            return;
        }
    }
    p_transaction->fun_work(p_param, p_transaction);
}

std::string module_sip::random_once(){
    return "123456";
}

bool module_sip::find_node_value(std::string& v, const char* pname, tinyxml2::XMLElement* pnode){
    if(nullptr == pname || nullptr == pnode){
        return false;
    }
    auto p = pnode->FirstChildElement(pname);
    if(nullptr == p){
        return false;
    }
    v = p->GetText();
    return true;
}
bool module_sip::find_node_value(std::string& v, const char* pname_first, const char* pname_second, tinyxml2::XMLElement* pnode){
    if(nullptr == pname_first || nullptr == pname_second || nullptr == pnode){
        return false;
    }
    tinyxml2::XMLElement *p = nullptr;
    if(nullptr == (p = pnode->FirstChildElement(pname_first)) || nullptr == (p = p->FirstChildElement(pname_second))){
        return false;
    }
    v = p->GetText();
    return true;
}

int module_sip::do_message_keepalive(info_param_ptr p_param, info_transaction_ptr p_transaction){
    // 设备状态信息报送消息
    p_transaction->status = STATUS_END;
    auto p_response = create_response_by_request(200, ACTION_OK, p_param);
    p_transaction->ptimer->send_buffer(create_buffer(p_response), p_param->point, p_param->p_socket);
    return MD_SUCCESS;
}

int module_sip::do_message(info_param_ptr , info_transaction_ptr ){
    return MD_UNKNOW;
}
