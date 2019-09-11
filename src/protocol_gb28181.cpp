#include "protocol_gb28181.h"
#include "utility_tool.h"
#include "error_code.h"

#define LINE_END "\r\n"

int protocol_gb28181::decode(info_param_ptr &p_param, frame_ptr &p_frame)
{
    if (!p_param)
    {
        p_param = std::make_shared<info_param>();
    }
    const char *p_data = reinterpret_cast<const char *>(p_frame->data());
    auto p_start = p_data;
    auto p_end = p_start + p_frame->size();
    bool flag_cmd_init = false;
    auto p_line_start = p_start, p_line_end = p_end, p_param_start = p_start, p_param_end = p_end, p_kv_start = p_start, p_kv_end = p_end;

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
            auto c = p_param_end - p_param_start;
            p_param->action = std::string(p_param_start, p_param_end - p_param_start);

            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
            {
                LOG_ERROR("找不到SIP协议地址:" << frame_to_str(p_frame));
                return false;
            }
            p_param->address = std::string(p_param_start, p_param_end - p_param_start);

            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
            {
                LOG_ERROR("找不到SIP协议版本:" << frame_to_str(p_frame));
                return false;
            }
            p_param->version = std::string(p_param_start, p_param_end - p_param_start);
        }
        else
        {
            if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ':'))
            {
                LOG_ERROR("找不到键值对分隔符:" << std::string(p_line_start, p_line_end - p_line_start));
                return false;
            }
            remove_char(&p_line_start, &p_line_end, ' ');
            std::string name(p_param_start, p_param_end);
            if (PARAM_VIA == name)
            {
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
                {
                    LOG_ERROR("找不到参数[Via@version]:" << std::string(p_line_start, p_line_end - p_line_start));
                    return false;
                }
                p_param->params[PARAM_VIA_VERSION] = std::string(p_param_start, p_param_end - p_param_start);
                p_param->params[PARAM_VIA_ADDRESS] = std::string(p_line_start, p_line_end - p_line_start);
            }else if (PARAM_FROM == name)
            {
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ';'))
                {
                    LOG_ERROR("找不到参数[From@sip]:" << std::string(p_line_start, p_line_end - p_line_start));
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
                    LOG_ERROR("找不到参数[To@sip]:" << std::string(p_line_start, p_line_end - p_line_start));
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
                    LOG_ERROR("找不到参数[CSeq@index]:" << std::string(p_line_start, p_line_end - p_line_start));
                    return false;
                }
                remove_char(&p_param_start, &p_param_end, ' ');
                p_param->params[PARAM_CSEQ_INDEX] = std::string(p_param_start, p_param_end);
                remove_char(&p_line_start, &p_line_end, ' ');
                p_param->params[PARAM_CSEQ_ACTION] = std::string(p_line_start, p_line_end - p_line_start);
            }else if (PARAM_AUTHENTICATE == name)
            {
                // 先去掉 Diges
                if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' '))
                {
                    LOG_ERROR("找不到参数[Authorization@Diges]:" << std::string(p_line_start, p_line_end - p_line_start));
                    return false;
                }
                decode_kv(p_param->params, "Authorization@", &p_line_start, p_line_end, ' ');
            }else{
                p_param->params[name] = std::string(p_line_start, p_line_end - p_line_start);
            }
        }
    }
}

int protocol_gb28181::encode(frame_ptr& p_frame, info_param_ptr& p_param){
    std::stringstream tmp_stream;
    tmp_stream<<p_param->version<<" "<<p_param->code<<" "<<p_param->action<<LINE_END;
    tmp_stream<<"Via: "<<p_param->params[PARAM_VIA_VERSION]<<" "<<p_param->params[PARAM_VIA_ADDRESS]<<LINE_END;
    tmp_stream<<"From: <"<<p_param->params[PARAM_FROM_SIP]<<">";
    if("" != p_param->params[PARAM_FROM_TAG]){
        tmp_stream<<";"<<p_param->params[PARAM_FROM_TAG]<<LINE_END;
    }else{
        tmp_stream<<LINE_END;
    }
    tmp_stream<<"To: <"<<p_param->params[PARAM_FROM_SIP]<<">"<<LINE_END;
    tmp_stream<<"Call-ID: "<<p_param->params[PARAM_CALL_ID]<<">"<<LINE_END;
    tmp_stream<<"CSeq: "<<p_param->params[PARAM_CSEQ_INDEX]<<" "<<p_param->params[PARAM_CSEQ_ACTION]<<LINE_END;

    for(auto& kv : p_param->params){
        if(std::string::npos == kv.first.find("@")){
            tmp_stream<<kv.first<<": "<<kv.second<<LINE_END;
        }
    }
    tmp_stream<<LINE_END;

    if(!p_frame){
        p_frame = std::make_shared<frame_ptr::element_type>();
    }else{
        p_frame->clear();
    }
    auto data = tmp_stream.str();
    for(auto& d : data){
        p_frame->push_back(d);
    }
    return ES_SUCCESS;
}

bool protocol_gb28181::find_line(const char **pp_line_start, const char **pp_line_end, const char **pp_start, const char *p_end)
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

bool protocol_gb28181::find_param(const char **pp_param_start, const char **pp_param_end, const char **pp_start, const char *p_end, const char s)
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
        return true;
    }
    return false;
}

bool protocol_gb28181::remove_char(const char **pp_start, const char **pp_end, const char s)
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
    for (auto p = *(pp_end - 1); p >= *pp_start; --p)
    {
        if (s != *p)
        {
            *pp_end = p + 1;
            break;
        }
    }
    return true;
}

bool protocol_gb28181::remove_rn(const char **pp_start, const char **pp_end)
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

bool protocol_gb28181::decode_kv(std::map<std::string, std::string> &kv, const std::string &tag, const char **pp_line_start, const char *p_line_end, const char s)
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
            LOG_ERROR("参数非键值对:" << std::string(p_param_start, p_param_end - p_param_start));
            continue;
        }
        remove_char(&p_kv_start, &p_kv_end, ' ');
        remove_char(&p_param_start, &p_param_end, ' ');
        remove_char(&p_param_start, &p_param_end, '\"');
        kv[tag + std::string(p_kv_start, p_kv_end - p_kv_start)] = std::string(p_param_start, p_param_end - p_param_start);
    }
}

std::string protocol_gb28181::random_str(){
    return "654321";
}