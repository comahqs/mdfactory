#include "server_sip.h"
#include "utility_tool.h"
#include "error_code.h"
#include <boost/format.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/shared_array.hpp>

#define LINE_END "\r\n"

#define STATUS_REGISTER_1 "REGISTER@1"
#define STATUS_REGISTER_3 "REGISTER@3"


#define ALGORITHM_MD5 "MD5"

#define ACTION_REGISTER "REGISTER"
#define ACTION_OK "OK"
#define ACTION_UNAUTHORIZED "Unauthorized"
#define ACTION_MESSAGE "MESSAGE"


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
#define PARAM_CONTENT_TYPE "Content-Type"
#define CONTENT_TYPE_XML "Application/MANSCDP+xml"

#define MESSAGE_NOTIFY_CMD_TYPE "Notify.CmdType"
#define MESSAGE_KEEPALIVE "Keepalive"

server_sip::~server_sip(){

}

void server_sip::on_read(frame_ptr& p_frame, std::size_t& count, point_type& point, socket_ptr& p_socket, context_ptr& p_context){
    info_param_ptr p_param = std::make_shared<info_param>();
    p_param->p_frame = std::make_shared<frame_ptr::element_type>(p_frame->begin(), p_frame->begin() + static_cast<int64_t>(count));
    if(MD_SUCCESS != decode(p_param, p_param->p_frame)){
        return;
    }
    info_net_ptr p_proxy;
    auto pnode_root = p_param->header.RootElement();
    auto pnode = pnode_root->FirstChildElement("address");
    if(nullptr == pnode){
        return;
    }
    auto iter = m_proxys.find(pnode->GetText());
    if(m_proxys.end() == iter){
        p_proxy = std::make_shared<info_net>();
        p_proxy->p_context = p_context;
        p_proxy->p_socket = p_socket;
        p_proxy->point = point;
        m_proxys.insert(std::make_pair(pnode->GetText(), p_proxy));
    }else{
        p_proxy = iter->second;
        if(p_proxy->point != point){
            LOG_WARN("源端端点改变; SIP地址"<<pnode->GetText()<<"; 旧端点:"<<p_proxy->point.address().to_string()<<"; 新端点:"<<point.address().to_string());
            p_proxy->point = point;
        }
    }
    p_proxy->params.push_back(p_param);
    
    do_work(p_proxy);
}

int server_sip::do_work(info_net_ptr p_info){
    std::string action, data;
    tinyxml2::XMLElement *pnode_root = nullptr;
    while(!p_info->params.empty()){
        auto p_param = *p_info->params.begin();
        p_info->params.erase(p_info->params.begin());

        pnode_root = p_param->header.RootElement();
        if(!find_node_value(action, "action", pnode_root)){
            LOG_ERROR("找不到action节点，数据将被抛弃");
            continue;
        }
        if(ACTION_REGISTER == action){
            // 注册 注销，区别是注销的Expires为0
            if(!find_node_value(data, "Authorization", "response", pnode_root)){
                // 没有鉴权的都认为是步骤1
                std::stringstream tmp_stream;

                encode_header(tmp_stream, 401, ACTION_UNAUTHORIZED, p_param, p_info);

                // WWW-Authenticate realm取项目编号，nonce取随机数
                tmp_stream<<"WWW-Authenticate: "<< (boost::format("Digest realm=\"%s\", nonce=\"%s\"")
                    % m_realm % random_str()).str()<<LINE_END;

                tmp_stream<<LINE_END;

                send_frame(tmp_stream.str(), p_info);
            }else{
                std::stringstream tmp_stream;
                encode_header(tmp_stream, 200, ACTION_OK, p_param, p_info);

                tmp_stream<<"Date: "<<ptime_to_param_date(boost::posix_time::second_clock::local_time())<<LINE_END;
                tmp_stream<<LINE_END;

                send_frame(tmp_stream.str(), p_info);
            }
        }else if(ACTION_MESSAGE == action){
            if(!find_node_value(data, PARAM_CONTENT_TYPE, pnode_root)){
                LOG_ERROR("消息缺失消息内容");
                return MD_MESSAGE_XML;
            }
            if(CONTENT_TYPE_XML != data){
                LOG_ERROR("无法处理的消息内容格式:"<<data);
                return MD_MESSAGE_XML;
            }
            pnode_root = p_param->data.RootElement();
            if(nullptr == pnode_root || !find_node_value(data, MESSAGE_NOTIFY_CMD_TYPE, pnode_root)){
                LOG_ERROR("找不到消息命令类型");
                return MD_MESSAGE_XML;
            }
            if(MESSAGE_KEEPALIVE == data){
                // 设备状态信息报送消息

                // 返回确认消息
                std::stringstream tmp_stream;
                encode_header(tmp_stream, 200, ACTION_OK, p_param, p_info);
                tmp_stream<<LINE_END;
                send_frame(tmp_stream.str(), p_info);
            }else{
                LOG_ERROR("无法处理的消息命令类型:"<<data);
                return MD_MESSAGE_XML;
            }
        }
    }
    
    return MD_SUCCESS;
}

int server_sip::encode_header(std::stringstream& stream, const int& code, const std::string& action, const info_param_ptr& p_param, const info_net_ptr& p_info){
    std::string data;
    auto pnode_root = p_param->header.RootElement();
    stream<<find_node_value("version", pnode_root)<<" "<<code<<" "<<action<<LINE_END;

    // 回应的To@sip优先Contact，然后From@sip
    if (find_node_value(data, PARAM_CONTACT, pnode_root)) {
        stream<<"To: <"<<data<<">"<<LINE_END;
    }else{
        stream<<"To: <"<< find_node_value(PARAM_FROM_SIP, pnode_root)<<">"<<LINE_END;
    }

    // 回应的From@sip为请求的To@sip; From@tag为请求的From@tag
    stream<<"From: <"<< find_node_value(PARAM_TO_SIP, pnode_root)<<">";
    if (find_node_value(data, PARAM_FROM_TAG, pnode_root)) {
        stream<<";tag="<<data<<LINE_END;
    }else{
        stream<<LINE_END;
    }

    stream<<"Via: "<<find_node_value(PARAM_VIA_VERSION, pnode_root);
    // Via@address需要设置成本地IP和端口
    // 直接取socket的本地地址，可能会取到0.0.0.0，所以这里还是取请求的Via中的地址
    auto address = p_info->p_socket->local_endpoint().address().to_string();
    if("0.0.0.0" == address || "127.0.0.1" == address){
        stream<<" "<<find_node_value(PARAM_VIA_POINT, pnode_root);
    }else{
        stream<<" "<<(boost::format("%s:%d") % p_info->p_socket->local_endpoint().address().to_string() % p_info->p_socket->local_endpoint().port()).str();
    }
    // rport增加端口
    if(find_node_value(data, "Via", "rport", pnode_root)){
        stream<<";rport="<<p_info->p_socket->local_endpoint().port();
    }
    // branch
    if(find_node_value(data, "Via", "branch", pnode_root)){
        stream<<";branch="<<data;
    }
    // 增加received，取远端端点
    stream<<";received="<<(boost::format("%s:%d") % p_info->p_socket->local_endpoint().address().to_string() % p_info->p_socket->local_endpoint().port()).str()<<LINE_END;

    stream<<"CSeq: "<<find_node_value(PARAM_CSEQ, pnode_root)<<LINE_END;
    stream<<"Call-ID: "<<find_node_value(PARAM_CALL_ID, pnode_root)<<LINE_END;
    stream<<"Max-Forwards: 70"<<LINE_END;
    stream<<"Expires: 3600"<<LINE_END;
    return MD_SUCCESS;
}

int server_sip::send_frame(frame_ptr p_frame, info_net_ptr p_info){
    LOG_INFO("发送数据:"<<frame_to_str(p_frame));
    p_info->p_socket->async_send_to(boost::asio::buffer(*p_frame, p_frame->size()), p_info->point, [p_frame](const boost::system::error_code& e, const std::size_t& ){
        if(e){
            LOG_ERROR("发送数据时发生错误:"<<e.message());
        }
    });
    return MD_SUCCESS;
}

int server_sip::send_frame(const std::string& data, info_net_ptr p_info){
    LOG_INFO("发送数据:"<<data);
    auto p_data = std::make_shared<std::string>(data);
    p_info->p_socket->async_send_to(boost::asio::buffer(p_data->c_str(), p_data->size()), p_info->point, [p_data](const boost::system::error_code& e, const std::size_t& ){
        if(e){
            LOG_ERROR("发送数据时发生错误:"<<e.message());
        }
    });
    return MD_SUCCESS;
}

std::string server_sip::ptime_to_param_date(const boost::posix_time::ptime& time){
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

int server_sip::decode(info_param_ptr &p_param, frame_ptr &p_frame)
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

    auto pnode_header_root = p_param->header.RootElement();
    tinyxml2::XMLElement* pnode = nullptr;
    auto pdoc = &p_param->header;
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
            flag_cmd_init = true;
            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
            {
                LOG_ERROR("找不到SIP协议动作:" << frame_to_str(p_frame));
                return false;
            }
            //p_param->action = std::string(p_param_start, static_cast<std::size_t>(p_param_end - p_param_start));
            put_node(pnode_header_root, "action", p_param_start, p_param_end, pdoc);

            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
            {
                LOG_ERROR("找不到SIP协议地址:" << frame_to_str(p_frame));
                return false;
            }
            //p_param->address = std::string(p_param_start, static_cast<std::size_t>(p_param_end - p_param_start));
            put_node(pnode_header_root, "address", p_param_start, p_param_end, pdoc);

            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
            {
                LOG_ERROR("找不到SIP协议版本:" << frame_to_str(p_frame));
                return false;
            }
            //p_param->version = std::string(p_param_start, static_cast<std::size_t>(p_param_end - p_param_start));
            put_node(pnode_header_root, "version", p_param_start, p_param_end, pdoc);
        }
        else
        {
            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ':'))
            {
                LOG_ERROR("找不到键值对分隔符:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                return false;
            }
            remove_char(&p_line_start, &p_line_end, ' ');
            pnode = put_node(pnode_header_root, p_param_start, p_param_end, p_line_start, p_line_end, pdoc);
            std::string name(p_param_start, p_param_end);
            if (PARAM_VIA == name)
            {
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
                {
                    LOG_ERROR("找不到参数[Via@version]:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                    return false;
                }
                put_node(pnode, PARAM_VIA_VERSION, p_param_start, p_param_end, pdoc);
                put_node(pnode, PARAM_VIA_ADDRESS, p_line_start, p_line_end, pdoc);
                // 尝试解析出端点
                if(find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ';')){
                    put_node(pnode, PARAM_VIA_POINT, p_param_start, p_param_end, pdoc);
                }
                decode_kv(pnode, "Via@", &p_line_start, p_line_end, ';', pdoc);
            }else if (PARAM_FROM == name)
            {
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ';'))
                {
                    LOG_ERROR("找不到参数[From@sip]:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                    return false;
                }
                remove_char(&p_param_start, &p_param_end, '<');
                remove_char(&p_param_start, &p_param_end, '>');
                put_node(pnode, PARAM_FROM_SIP, p_param_start, p_param_end, pdoc);
                decode_kv(pnode, "From@", &p_line_start, p_line_end, ';', pdoc);
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
                put_node(pnode, PARAM_TO_SIP, p_param_start, p_param_end, pdoc);
                decode_kv(pnode, "To@", &p_line_start, p_line_end, ';', pdoc);
            }else if (PARAM_CSEQ == name)
            {
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
                {
                    LOG_ERROR("找不到参数[CSeq@index]:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                    return false;
                }
                remove_char(&p_param_start, &p_param_end, ' ');
                put_node(pnode, PARAM_CSEQ_INDEX, p_param_start, p_param_end, pdoc);
                remove_char(&p_line_start, &p_line_end, ' ');
                put_node(pnode, PARAM_CSEQ_ACTION, p_line_start, p_line_end, pdoc);
            }else if (PARAM_AUTHENTICATE == name)
            {
                // 先去掉 Diges
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
                {
                    LOG_ERROR("找不到参数[Authorization@Diges]:" << std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
                    return false;
                }
                decode_kv(pnode, "Authorization@", &p_line_start, p_line_end, ' ', pdoc);
            }else if (PARAM_CONTACT == name)
            {
                remove_char(&p_line_start, &p_line_end, '<');
                remove_char(&p_line_start, &p_line_end, '>');
                put_node(pnode, name.c_str(), p_line_start, p_line_end, pdoc);
            }else{
                put_node(pnode, name.c_str(), p_line_start, p_line_end, pdoc);
            }
        }
    }

    // 看是不是有数据体需要解析
    pnode = pnode_header_root->FirstChildElement(PARAM_CONTENT_TYPE);
    if(nullptr != pnode && 0 < (p_end - p_start)){
        if(0 >= (p_end - p_start)){
            LOG_ERROR("有数据体标识，但没有数据体内容:"<<pnode->GetText());
            return MD_PROTOCOL_DATA;
        }
        if(0 == strcmp(CONTENT_TYPE_XML, pnode->GetText())){
            try{
                auto vcount = static_cast<std::size_t>(p_end - p_start);
                auto pbuffer = boost::shared_array<char>(new char[vcount + 1]);
                memcpy(pbuffer.get(), p_start, vcount);
                (pbuffer.get())[vcount] = '\0';
                p_param->data.Parse(pbuffer.get());
            }catch(const std::exception& e){
                LOG_ERROR("解析XML数据时发生错误:"<<e.what());
                return MD_MESSAGE_XML;
            }
        }else{
            LOG_WARN("无法处理的数据体:"<<pnode->GetText());
        }
    }
    return MD_SUCCESS;
}

bool server_sip::find_line(const char **pp_line_start, const char **pp_line_end, const char **pp_start, const char *p_end)
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

bool server_sip::find_param(const char **pp_param_start, const char **pp_param_end, const char **pp_start, const char *p_end, const char s)
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

bool server_sip::remove_char(const char **pp_start, const char **pp_end, const char s)
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

bool server_sip::remove_rn(const char **pp_start, const char **pp_end)
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

bool server_sip::decode_kv(std::map<std::string, std::string> &kv, const std::string &tag, const char **pp_line_start, const char *p_line_end, const char s)
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

bool server_sip::decode_kv(tinyxml2::XMLElement* p_parent, const std::string& tag, const char **pp_line_start, const char *p_line_end, const char s, tinyxml2::XMLDocument *pdoc){
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
            std::string name = tag + std::string(p_kv_start, static_cast<std::size_t>(p_kv_end - p_kv_start));
            put_node(p_parent, name.c_str(), nullptr, nullptr, pdoc);
        }else{
            remove_char(&p_kv_start, &p_kv_end, ' ');
            remove_char(&p_param_start, &p_param_end, ' ');
            remove_char(&p_param_start, &p_param_end, '\"');
            std::string name = tag + std::string(p_kv_start, static_cast<std::size_t>(p_kv_end - p_kv_start));
            put_node(p_parent, name.c_str(), p_param_start, p_param_end, pdoc);
        }
    }
    return true;
}

std::string server_sip::random_str(){
    return "654321";
}

tinyxml2::XMLElement* server_sip::put_node(tinyxml2::XMLElement* p_parent, const char* pname, const char *pvalue_start, const char *pvalue_end, tinyxml2::XMLDocument *pdoc){
    if(nullptr == p_parent || nullptr == pname || nullptr == pdoc){
        return nullptr;
    }
    auto vcount = static_cast<std::size_t>(pvalue_end - pvalue_start);
    auto pbuffer = boost::shared_array<char>(new char[vcount + 1]);
    auto pnode = pdoc->NewElement(pname);
    memcpy(pbuffer.get(), pvalue_start, vcount);
    (pbuffer.get())[vcount] = '\0';
    pnode->SetText(pbuffer.get());
    p_parent->InsertEndChild(pnode);
    return pnode;
}

tinyxml2::XMLElement* server_sip::put_node(tinyxml2::XMLElement* p_parent, const char* pname_start, const char* pname_end, const char *pvalue_start, const char *pvalue_end, tinyxml2::XMLDocument *pdoc){
    if(nullptr == p_parent || nullptr == pname_start || nullptr == pname_end || nullptr == pdoc){
        return nullptr;
    }
    auto ncount = static_cast<std::size_t>(pname_end - pname_start);
    auto vcount = static_cast<std::size_t>(pvalue_end - pvalue_start);
    auto pbuffer = boost::shared_array<char>(new char[std::max(ncount, vcount) + 1]);
    memcpy(pbuffer.get(), pname_start, ncount);
    (pbuffer.get())[ncount] = '\0';
    auto pnode = pdoc->NewElement(pbuffer.get());
    memcpy(pbuffer.get(), pvalue_start, vcount);
    (pbuffer.get())[vcount] = '\0';
    pnode->SetText(pbuffer.get());
    p_parent->InsertEndChild(pnode);
    return pnode;
}

bool server_sip::find_node_value(std::string& v, const char* pname, tinyxml2::XMLElement* pnode){
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
bool server_sip::find_node_value(std::string& v, const char* pname_first, const char* pname_second, tinyxml2::XMLElement* pnode){
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

std::string server_sip::find_node_value(const char* pname, tinyxml2::XMLElement* pnode){
    if(nullptr == pname || nullptr == pnode){
        return "";
    }
    auto p = pnode->FirstChildElement(pname);
    if(nullptr == p){
        return "";
    }
    return p->GetText();
}
