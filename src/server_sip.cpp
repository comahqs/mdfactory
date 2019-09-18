#include "server_sip.h"
#include "utility_tool.h"
#include "error_code.h"
#include "module_timer.h"

server_sip::~server_sip(){

}

void server_sip::on_read(frame_ptr& p_buffer, std::size_t& count, point_type& point, socket_ptr& p_socket, context_ptr& pcontext){
    info_param_ptr p_param = std::make_shared<info_param>();
    p_param->p_socket = p_socket;
    p_param->point = point;
    auto p_frame = std::make_shared<frame_ptr::element_type>(p_buffer->begin(), p_buffer->begin() + static_cast<int64_t>(count));
    if(MD_SUCCESS != mp_module->decode(p_param, p_frame)){
        return;
    }
    auto p_transaction = get_transaction(p_param, pcontext);
    if(!p_transaction){
        return;
    }
    p_transaction->fun_work(p_param, p_transaction);

    // 如果事务结束了，就删除
    if(STATUS_END == p_transaction->status){
        m_transactions.erase(p_transaction->id);
    }
}

info_transaction_ptr server_sip::get_transaction(info_param_ptr p_param, context_ptr& pcontext){
    // 事务相等的条件  1、Via.branch相等；2、CSeq.method相等。
    info_transaction_ptr p_transaction;
    if(!p_param){
        return info_transaction_ptr();
    }
    std::string id_transaction;
    if(!mp_module->get_transaction_id(id_transaction, p_param)){
        LOG_ERROR("生成事务id失败");
        return info_transaction_ptr();
    }
    auto iter = m_transactions.find(id_transaction);
    if(m_transactions.end() == iter){
        p_transaction = std::make_shared<info_transaction_ptr::element_type>();
        p_transaction->id = id_transaction;
        p_transaction->ptimer = std::make_shared<module_timer>(*pcontext, std::bind(server_sip::handle_cancel, std::weak_ptr<server_sip>(shared_from_this()), p_transaction->id), m_time_resend, m_time_cancel);
    }else{
        p_transaction = iter->second;
    }
    p_transaction->params.insert(std::make_pair(p_transaction->status, p_param));
    return p_transaction;
}

void server_sip::handle_cancel(std::weak_ptr<server_sip> pserver, std::string id_transaction){
    auto p = pserver.lock();
    if(!p){
        return;
    }
    p->m_transactions.erase(id_transaction);
}

int server_sip::decode_sdp(info_param_ptr& , const char** , const char** ){
    /*
    auto pnode_header_root = nullptr;
    const char *p_line_start = nullptr, *p_line_end = nullptr, *p_param_start = nullptr, *p_param_end = nullptr;
    tinyxml2::XMLElement *pnode = nullptr;
    while(true){
        if (!find_line(&p_line_start, &p_line_end, pp_start, *pp_end))
        {
            break;
        }
        if (p_line_start == p_line_end)
        {
            break;
        }
        if (!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, '='))
        {
            LOG_ERROR("非法SDP参数:"<<std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
            continue;
        }
        remove_char(&p_param_start, &p_param_start, ' ');
        remove_char(&p_line_start, &p_line_end, ' ');
        if(p_param_start == p_param_end){
            LOG_ERROR("非法SDP参数:"<<std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start)));
            continue;
        }

        if(1 == (p_param_end - p_param_start)){
            if('v' == *p_param_start){
                // protocol version
                pnode = put_node(pnode_header_root, "v_version", p_line_start, p_line_end, &p_param->data);
            }else if('o' == *p_param_start){
                // owner/creator and session identifier
                // o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
                while(true){
                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "o_username", p_param_start, p_param_end, &p_param->data);

                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "o_sess-id", p_param_start, p_param_end, &p_param->data);

                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "o_sess-version", p_param_start, p_param_end, &p_param->data);

                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "o_nettype", p_param_start, p_param_end, &p_param->data);

                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "o_addrtype", p_param_start, p_param_end, &p_param->data);

                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "o_unicast-address", p_param_start, p_param_end, &p_param->data);
                    break;
                }
            }else if('s' == *p_param_start){
                // session name
                put_node(pnode_header_root, "s", p_param_start, p_param_end, &p_param->data);
            }else if('c' == *p_param_start){
                // connection information
                // 网络协议，地址的类型，连接地址
                while(true){
                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "c_nettype", p_param_start, p_param_end, &p_param->data);

                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "c_addrtype", p_param_start, p_param_end, &p_param->data);

                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "c_unicast-address", p_param_start, p_param_end, &p_param->data);
                    break;
                }
            }else if('t' == *p_param_start){
                // time the session is active
                // 开始时间，结束时间
                while(true){
                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "t_start", p_param_start, p_param_end, &p_param->data);

                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "t_end", p_param_start, p_param_end, &p_param->data);
                    break;
                }
            }else if('m' == *p_param_start){
                // media name and transport address
                // <media> <port> <proto> <fmt> ...
                while(true){
                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "m_media", p_param_start, p_param_end, &p_param->data);

                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "m_port", p_param_start, p_param_end, &p_param->data);

                    if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                        break;
                    }
                    put_node(pnode_header_root, "m_protocol", p_param_start, p_param_end, &p_param->data);

                    pnode = put_node(pnode_header_root, "m_fmt", p_param_start, p_param_end, &p_param->data);
                    while(true){
                        if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                            break;
                        }
                        put_node(pnode, p_param_start, p_param_end, p_param_start, p_param_end, &p_param->data);
                    }
                    break;
                }
            }else if('a' == *p_param_start){
                // media attribute

                const char *p_kv_start = nullptr, *p_kv_end = nullptr;
                if(!find_param(&p_kv_start, &p_kv_end, &p_line_start, p_line_end, ':')){
                    // 没有:分隔的属性，只能是sendonly/recvonly/sendrecv/inactive
                    std::string k = (boost::format("a_%s") % std::string(p_line_start, static_cast<std::size_t>(p_line_end - p_line_start))).str();
                    put_node(pnode_header_root, k.data(), p_line_start, p_line_end, &p_param->data);
                }else{
                     std::string k = (boost::format("a_%s") % std::string(p_kv_start, static_cast<std::size_t>(p_kv_end - p_kv_start))).str();
                     pnode = put_node(pnode_header_root, k.data(), p_line_start, p_line_end, &p_param->data);
                     while(true){
                         if(!find_param(&p_param_start, &p_param_end, &p_line_start, p_line_end, ' ')){
                             break;
                         }
                         put_node(pnode, p_param_start, p_param_end, p_param_start, p_param_end, &p_param->data);
                     }
                }
            }
        }
    }
    */
    return MD_SUCCESS;
}
