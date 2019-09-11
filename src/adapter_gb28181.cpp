#include "adapter_gb28181.h"
#include "utility_tool.h"
#include "error_code.h"
#include <boost/format.hpp>

#define LINE_END "\r\n"

#define STATUS_REGISTER_1 "REGISTER@1"
#define STATUS_REGISTER_3 "REGISTER@3"


#define ALGORITHM_MD5 "MD5"

#define ACTION_REGISTER "REGISTER"
#define ACTION_OK "OK"
#define ACTION_UNAUTHORIZED "Unauthorized"
#define PARAM_TAG "tag"
#define PARAM_VIA "Via"
#define PARAM_VIA_POINT "Via@point"
#define PARAM_VIA_VERSION "Via@version"
#define PARAM_VIA_ADDRESS "Via@address"
#define PARAM_FROM "From"
#define PARAM_FROM_SIP "From@sip"
#define PARAM_FROM_TAG "From@tag"
#define PARAM_TO "To"
#define PARAM_TO_SIP "To@sip"
#define PARAM_TO_TAG "To@tag"
#define PARAM_VIA_ADDRESS "Via@address"
#define PARAM_WWW_AUTHENTICATE "WWW-Authenticate"
#define PARAM_CSEQ "CSeq"
#define PARAM_CSEQ_INDEX "CSeq@index"
#define PARAM_CSEQ_ACTION "CSeq@action"
#define PARAM_AUTHENTICATE "Authorization"
#define PARAM_AUTHENTICATE_USERNAME "Authorization@username"
#define PARAM_AUTHENTICATE_REALM "Authorization@realm"
#define PARAM_AUTHENTICATE_NONCE "Authorization@nonce"
#define PARAM_AUTHENTICATE_URI "Authorization@uri"
#define PARAM_AUTHENTICATE_RESPONSE "Authorization@response"
#define PARAM_AUTHENTICATE_ALGORITHM "Authorization@algorithm"
#define PARAM_DATE "Date"
#define PARAM_CALL_ID "Call-ID"
#define PARAM_CONTACT "Contact"
#define PARAM_MAX_FORWARDS "Max-Forwards"
#define PARAM_EXPIRES "Expires"
#define PARAM_CONTENT_LENGTH "Content-Length"

adapter_gb28181::~adapter_gb28181(){

}

void adapter_gb28181::on_read(frame_ptr& p_frame, std::size_t& count, point_type& point, socket_ptr& p_socket, context_ptr& p_context){
    info_param_ptr p_param = std::make_shared<info_param>();
    p_param->p_frame = std::make_shared<frame_ptr::element_type>(p_frame->begin(), p_frame->begin() + static_cast<int64_t>(count));
    if(ES_SUCCESS != decode(p_param, p_param->p_frame)){
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
    p_proxy->params.push_back(p_param);
    
    do_work(p_proxy);
}

int adapter_gb28181::do_work(info_net_proxy_ptr p_info){
    while(!p_info->params.empty()){
        auto p_param = *p_info->params.begin();
        p_info->params.erase(p_info->params.begin());

        if(ACTION_REGISTER == p_param->action && "1" == p_param->params[PARAM_CSEQ_INDEX]){
            p_info->status = STATUS_REGISTER_1;
            std::stringstream tmp_stream;

            tmp_stream<<p_param->version<<" "<<401<<" "<<ACTION_UNAUTHORIZED<<LINE_END;

            // 回应的To@sip优先Contact，然后From@sip
            auto iter = p_param->params.find(PARAM_CONTACT);
            if (p_param->params.end() == iter) {
                tmp_stream<<"To: <"<< iter->second<<">"<<LINE_END;
            }else{
                tmp_stream<<"To: <"<< p_param->params[PARAM_FROM_SIP]<<">"<<LINE_END;
            }

            // 回应的From@sip为请求的To@sip; From@tag为请求的From@tag
            tmp_stream<<"From: <"<< p_param->params[PARAM_TO_SIP]<<">";
            iter = p_param->params.find(PARAM_FROM_TAG);
            if (p_param->params.end() != iter) {
                tmp_stream<<";tag="<<iter->second<<LINE_END;
            }else{
                tmp_stream<<LINE_END;
            }

            tmp_stream<<"Via: "<<p_param->params[PARAM_VIA_VERSION];
            // Via@address需要设置成本地IP和端口
            // 直接取socket的本地地址，可能会取到0.0.0.0，所以这里还是取请求的Via中的地址
            auto address = p_info->p_socket->local_endpoint().address().to_string();
            if("0.0.0.0" == address || "127.0.0.1" == address){
                tmp_stream<<" "<<p_param->params[PARAM_VIA_POINT];
            }else{
                tmp_stream<<" "<<(boost::format("%s:%d") % p_info->p_socket->local_endpoint().address().to_string() % p_info->p_socket->local_endpoint().port()).str();
            }
            // rport增加端口
            if(p_param->params.end() != p_param->params.find("Via@rport")){
                tmp_stream<<";rport="<<p_info->p_socket->local_endpoint().port();
            }
            // branch
             iter = p_param->params.find("Via@branch");
            if(p_param->params.end() != iter){
                tmp_stream<<";branch="<<iter->second;
            }
            // 增加received，取远端端点
            tmp_stream<<";received="<<(boost::format("%s:%d") % p_info->p_socket->local_endpoint().address().to_string() % p_info->p_socket->local_endpoint().port()).str()<<LINE_END;
            
            // WWW-Authenticate realm取项目编号，nonce取随机数
            tmp_stream<<"WWW-Authenticate: "<< (boost::format("Digest realm=\"%s\", nonce=\"%s\"")
                % m_realm % random_str()).str()<<LINE_END;
            
            tmp_stream<<"CSeq: "<<p_param->params[PARAM_CSEQ_INDEX]<<" "<<p_param->params[PARAM_CSEQ_ACTION]<<LINE_END;
            tmp_stream<<"Call-ID: "<<p_param->params[PARAM_CALL_ID]<<LINE_END;
            tmp_stream<<"Max-Forwards: 70"<<LINE_END;
            tmp_stream<<"Expires: 3600"<<LINE_END;
            tmp_stream<<LINE_END;

            send_frame(tmp_stream.str(), p_info);
        }else if(ACTION_REGISTER == p_param->action  && "2" == p_param->params[PARAM_CSEQ_INDEX] && STATUS_REGISTER_1 == p_info->status){
            p_info->status = STATUS_REGISTER_3;
            auto p_response = std::make_shared<info_param>();

            std::stringstream tmp_stream;

            tmp_stream<<p_param->version<<" "<<200<<" "<<ACTION_OK<<LINE_END;

            // 回应的To@sip优先Contact，然后From@sip
            auto iter = p_param->params.find(PARAM_CONTACT);
            if (p_param->params.end() == iter) {
                tmp_stream<<"To: <"<< iter->second<<">"<<LINE_END;
            }else{
                tmp_stream<<"To: <"<< p_param->params[PARAM_FROM_SIP]<<">"<<LINE_END;
            }

            // 回应的From@sip为请求的To@sip; From@tag为请求的From@tag
            tmp_stream<<"From: <"<< p_param->params[PARAM_TO_SIP]<<">";
            iter = p_param->params.find(PARAM_FROM_TAG);
            if (p_param->params.end() != iter) {
                tmp_stream<<";tag="<<iter->second<<LINE_END;
            }else{
                tmp_stream<<LINE_END;
            }

            tmp_stream<<"Via: "<<p_param->params[PARAM_VIA_VERSION];
            // Via@address需要设置成本地IP和端口
            // 直接取socket的本地地址，可能会取到0.0.0.0，所以这里还是取请求的Via中的地址
            auto address = p_info->p_socket->local_endpoint().address().to_string();
            if("0.0.0.0" == address || "127.0.0.1" == address){
                tmp_stream<<" "<<p_param->params[PARAM_VIA_POINT];
            }else{
                tmp_stream<<" "<<(boost::format("%s:%d") % p_info->p_socket->local_endpoint().address().to_string() % p_info->p_socket->local_endpoint().port()).str();
            }
            // rport增加端口
            if(p_param->params.end() != p_param->params.find("Via@rport")){
                tmp_stream<<";rport="<<p_info->p_socket->local_endpoint().port();
            }
            // branch
             iter = p_param->params.find("Via@branch");
            if(p_param->params.end() != iter){
                tmp_stream<<";branch="<<iter->second;
            }
            // 增加received，取远端端点
            tmp_stream<<";received="<<(boost::format("%s:%d") % p_info->p_socket->local_endpoint().address().to_string() % p_info->p_socket->local_endpoint().port()).str()<<LINE_END;

            // WWW-Authenticate realm取项目编号，nonce取随机数
            tmp_stream<<"WWW-Authenticate: "<< (boost::format("Digest realm=\"%s\", nonce=\"%s\"")
                % m_realm % random_str()).str()<<LINE_END;

            p_response->params[PARAM_DATE] = ptime_to_param_date(boost::posix_time::second_clock::local_time());

            tmp_stream<<"CSeq: "<<p_param->params[PARAM_CSEQ_INDEX]<<" "<<p_param->params[PARAM_CSEQ_ACTION]<<LINE_END;
            tmp_stream<<"Call-ID: "<<p_param->params[PARAM_CALL_ID]<<LINE_END;
            tmp_stream<<"Max-Forwards: 70"<<LINE_END;
            tmp_stream<<"Expires: 3600"<<LINE_END;
            tmp_stream<<LINE_END;

            send_frame(tmp_stream.str(), p_info);
        }
    }
    
    return 0;
}

int adapter_gb28181::send_frame(frame_ptr p_frame, info_net_proxy_ptr p_info){
    LOG_INFO("发送数据:"<<frame_to_str(p_frame));
    p_info->p_socket->async_send_to(boost::asio::buffer(*p_frame, p_frame->size()), p_info->point, [p_frame](const boost::system::error_code& e, const std::size_t& ){
        if(e){
            LOG_ERROR("发送数据时发生错误:"<<e.message());
        }
    });
    return ES_SUCCESS;
}

int adapter_gb28181::send_frame(const std::string& data, info_net_proxy_ptr p_info){
    LOG_INFO("发送数据:"<<data);
    auto p_data = std::make_shared<std::string>(data);
    p_info->p_socket->async_send_to(boost::asio::buffer(p_data->c_str(), p_data->size()), p_info->point, [p_data](const boost::system::error_code& e, const std::size_t& ){
        if(e){
            LOG_ERROR("发送数据时发生错误:"<<e.message());
        }
    });
    return ES_SUCCESS;
}

std::string adapter_gb28181::ptime_to_param_date(const boost::posix_time::ptime& time){
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

int adapter_gb28181::decode(info_param_ptr &p_param, frame_ptr &p_frame)
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
        if (!find_line(&p_line_start, &p_line_end, &p_start, p_end))
        {
            break;
        }
        if (p_line_start == p_line_end)
        {
            continue;
        }
        if (!flag_cmd_init)
        {
            flag_cmd_init = true;
            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
            {
                LOG_ERROR("找不到SIP协议动作:" << frame_to_str(p_frame));
                return false;
            }
            p_param->action = std::string(p_param_start, static_cast<std::size_t>(p_param_end - p_param_start));

            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
            {
                LOG_ERROR("找不到SIP协议地址:" << frame_to_str(p_frame));
                return false;
            }
            p_param->address = std::string(p_param_start, static_cast<std::size_t>(p_param_end - p_param_start));

            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
            {
                LOG_ERROR("找不到SIP协议版本:" << frame_to_str(p_frame));
                return false;
            }
            p_param->version = std::string(p_param_start, static_cast<std::size_t>(p_param_end - p_param_start));
        }
        else
        {
            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ':'))
            {
                LOG_ERROR("找不到键值对分隔符:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                return false;
            }
            remove_char(&p_line_start, &p_line_end, ' ');
            std::string name(p_param_start, p_param_end);
            if (PARAM_VIA == name)
            {
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
                {
                    LOG_ERROR("找不到参数[Via@version]:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                    return false;
                }
                p_param->params[PARAM_VIA_VERSION] = std::string(p_param_start, static_cast<std::size_t>(p_param_end - p_param_start));
                p_param->params[PARAM_VIA_ADDRESS] = std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start));
                // 尝试解析出端点
                if(find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ';')){
                    p_param->params[PARAM_VIA_POINT] = std::string(p_param_start, static_cast<std::size_t>(p_param_end - p_param_start));
                }
                decode_kv(p_param->params, "Via@", &p_line_start, p_line_end, ';');
            }else if (PARAM_FROM == name)
            {
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ';'))
                {
                    LOG_ERROR("找不到参数[From@sip]:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                    return false;
                }
                remove_char(&p_param_start, &p_param_end, '<');
                remove_char(&p_param_start, &p_param_end, '>');
                p_param->params.insert(std::make_pair(PARAM_FROM_SIP, std::string(p_param_start, p_param_end)));

                decode_kv(p_param->params, "From@", &p_line_start, p_line_end, ';');
            }
            else if (PARAM_TO == name)
            {
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ';'))
                {
                    LOG_ERROR("找不到参数[To@sip]:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                    return false;
                }
                remove_char(&p_param_start, &p_param_end, '<');
                remove_char(&p_param_start, &p_param_end, '>');
                p_param->params.insert(std::make_pair(PARAM_TO_SIP, std::string(p_param_start, p_param_end)));

                decode_kv(p_param->params, "To@", &p_line_start, p_line_end, ';');
            }else if (PARAM_CSEQ == name)
            {
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
                {
                    LOG_ERROR("找不到参数[CSeq@index]:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                    return false;
                }
                remove_char(&p_param_start, &p_param_end, ' ');
                p_param->params[PARAM_CSEQ_INDEX] = std::string(p_param_start, p_param_end);
                remove_char(&p_line_start, &p_line_end, ' ');
                p_param->params[PARAM_CSEQ_ACTION] = std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start));
            }else if (PARAM_AUTHENTICATE == name)
            {
                // 先去掉 Diges
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
                {
                    LOG_ERROR("找不到参数[Authorization@Diges]:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                    return false;
                }
                decode_kv(p_param->params, "Authorization@", &p_line_start, p_line_end, ' ');
            }else if (PARAM_CONTACT == name)
            {
                remove_char(&p_line_start, &p_line_end, '<');
                remove_char(&p_line_start, &p_line_end, '>');
                p_param->params[name] = std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start));
            }else{
                p_param->params[name] = std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start));
            }
        }
    }
    return ES_SUCCESS;
}

bool adapter_gb28181::find_line(const char **pp_line_start, const char **pp_line_end, const char **pp_start, const char *p_end)
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

bool adapter_gb28181::find_param(const char **pp_param_start, const char **pp_param_end, const char **pp_start, const char *p_end, const char s)
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

bool adapter_gb28181::remove_char(const char **pp_start, const char **pp_end, const char s)
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

bool adapter_gb28181::remove_rn(const char **pp_start, const char **pp_end)
{
    if (nullptr == pp_start || nullptr == pp_end)
    {
        return false;
    }
    if (*pp_start == *pp_end)
    {
        return true;
    }
    for (auto p = *(pp_end - 1); p >= *pp_start; --p)
    {
        if ('\n' != *p && '\r' != *p)
        {
            *pp_end = p + 1;
            break;
        }
    }
    return true;
}

bool adapter_gb28181::decode_kv(std::map<std::string, std::string> &kv, const std::string &tag, const char **pp_line_start, const char *p_line_end, const char s)
{
    const char* p_param_start = nullptr, *p_param_end = nullptr, *p_kv_start = nullptr, *p_kv_end = nullptr;
    while (true)
    {
        if (!find_param(&p_param_start, &p_param_end, pp_line_start, p_line_end, s))
        {
            break;
        }
        if (!find_param(&p_kv_start, &p_kv_end, &p_param_start, p_param_end, '='))
        {
            remove_char(&p_kv_start, &p_kv_end, ' ');
            kv[tag + std::string(p_kv_start, static_cast<std::size_t>(p_kv_end - p_kv_start))] = std::string();
        }else{
            remove_char(&p_kv_start, &p_kv_end, ' ');
            remove_char(&p_param_start, &p_param_end, ' ');
            remove_char(&p_param_start, &p_param_end, '\"');
            kv[tag + std::string(p_kv_start, static_cast<std::size_t>(p_kv_end - p_kv_start))] = std::string(p_param_start, static_cast<std::size_t>(p_param_end - p_param_start));
        }
    }
    return true;
}

std::string adapter_gb28181::random_str(){
    return "654321";
}
