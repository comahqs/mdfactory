#include "server_sip.h"
#include "utility_tool.h"
#include "error_code.h"
#include "module_timer.h"
#include <boost/format.hpp>
#include <sstream>
#include <pjsip/sip_auth_parser.h>
#include <pjsip/sip_endpoint.h>

#define LOG_ERROR_PJ(MSG)                                        \
    {                                                            \
        std::stringstream tmp_stream;                            \
        tmp_stream << MSG;                                       \
        PJ_LOG(1, ("server_sip.cpp", tmp_stream.str().c_str())); \
    }
#define LOG_WARN_PJ(MSG)                                         \
    {                                                            \
        std::stringstream tmp_stream;                            \
        tmp_stream << MSG;                                       \
        PJ_LOG(2, ("server_sip.cpp", tmp_stream.str().c_str())); \
    }
#define LOG_INFO_PJ(MSG)                                         \
    {                                                            \
        std::stringstream tmp_stream;                            \
        tmp_stream << MSG;                                       \
        PJ_LOG(3, ("server_sip.cpp", tmp_stream.str().c_str())); \
    }
#define LOG_DEBUG_PJ(MSG)                                        \
    {                                                            \
        std::stringstream tmp_stream;                            \
        tmp_stream << MSG;                                       \
        PJ_LOG(4, ("server_sip.cpp", tmp_stream.str().c_str())); \
    }

pj_caching_pool server_sip::m_cp;
pjsip_endpoint *server_sip::mp_sip_endpt = nullptr;

server_sip::server_sip(const int &port) : m_port(port)
{
}

server_sip::~server_sip()
{
}

bool server_sip::start()
{
    pj_status_t status;

    /* Must init PJLIB first: */
    status = pj_init();
    if (PJ_SUCCESS != status)
    {
        LOG_ERROR_PJ("初始化[pj_init]失败:" << status);
        return false;
    }
    /* Then init PJLIB-UTIL: */
    status = pjlib_util_init();
    if (PJ_SUCCESS != status)
    {
        LOG_ERROR_PJ("初始化[pjlib_util_init]失败:" << status);
        return false;
    }

    /* Must create a pool factory before we can allocate any memory. */
    pj_caching_pool_init(&m_cp, &pj_pool_factory_default_policy, 0);

    /* Create the endpoint: */
    status = pjsip_endpt_create(&m_cp.factory, "sipstateless",
                                &mp_sip_endpt);
    if (PJ_SUCCESS != status)
    {
        LOG_ERROR_PJ("创建pj端点失败:" << status);
        return false;
    }

    /*
         * Add UDP transport, with hard-coded port
         */
    pj_sockaddr_in addr;

    addr.sin_family = pj_AF_INET();
    addr.sin_addr.s_addr = 0;
    addr.sin_port = pj_htons(static_cast<pj_uint16_t>(m_port));

    status = pjsip_udp_transport_start(mp_sip_endpt, &addr, nullptr, 1, nullptr);
    if (status != PJ_SUCCESS)
    {
        LOG_ERROR_PJ("创建udp传输失败:" << status);
        return false;
    }

    status = pjsip_tsx_layer_init_module(mp_sip_endpt);
    if (status != PJ_SUCCESS)
    {
        LOG_ERROR_PJ("初始化事务层模块失败:" << status);
        return false;
    }

    status = pjsip_ua_init_module(mp_sip_endpt, NULL);
    if (status != PJ_SUCCESS)
    {
        LOG_ERROR_PJ("初始化ua层模块失败:" << status);
        return false;
    }

    /*
         * Register our module to receive incoming requests.
         */
    m_module.name = {"server_sip"};
    m_module.id = -1;
    m_module.load = nullptr;
    m_module.unload = nullptr;
    m_module.start = nullptr;
    m_module.stop = nullptr;
    m_module.priority = PJSIP_MOD_PRIORITY_APPLICATION;
    m_module.on_rx_request = &server_sip::on_rx_request;
    m_module.on_rx_response = &server_sip::on_rx_response;
    m_module.on_tx_request = &server_sip::on_tx_request;
    m_module.on_tx_response = nullptr;
    m_module.on_tsx_state = &server_sip::on_tsx_state;

    status = pjsip_endpt_register_module(mp_sip_endpt, &m_module);
    if (status != PJ_SUCCESS)
    {
        LOG_ERROR_PJ("注册自定义模块失败:" << status);
        return false;
    }

    auto pool = pjsip_endpt_create_pool(mp_sip_endpt, "", 1000, 1000);
    if (nullptr == pool || !pool)
    {
        LOG_ERROR_PJ("创建内存池失败:" << status);
        return false;
    }

    m_flag = PJ_TRUE;
    m_thread_params.first = mp_sip_endpt;
    m_thread_params.second = &m_flag;
    status = pj_thread_create(pool, "", server_sip::worker_thread, &m_thread_params, 0, 0, &mp_thread);
    if (PJ_SUCCESS != status)
    {
        LOG_ERROR_PJ("创建工作线程失败:" << status);
        return false;
    }
    return true;
}

void server_sip::stop()
{
}

pj_bool_t server_sip::on_rx_request(pjsip_rx_data *rdata)
{
    LOG_DEBUG_PJ("on_rx_request");
    pj_status_t status;
    if (pjsip_method_e::PJSIP_REGISTER_METHOD == rdata->msg_info.cseq->method.id)
    {
        // REGISTER
        auto hdr = (pjsip_www_authenticate_hdr *)pjsip_msg_find_hdr(rdata->msg_info.msg, pjsip_hdr_e::PJSIP_H_AUTHORIZATION, nullptr);
        if (nullptr == hdr)
        {
            // 2
            hdr = pjsip_www_authenticate_hdr_create(rdata->tp_info.pool);
            char nonce_buf[16];
            pj_str_t random;
            random.ptr = nonce_buf;
            random.slen = sizeof(nonce_buf);
            hdr->scheme = pjsip_DIGEST_STR;
            //hdr->challenge.digest.algorithm = pjsip_MD5_STR;
            pj_create_random_string(nonce_buf, sizeof(nonce_buf));
            pj_strdup2(rdata->tp_info.pool, &hdr->challenge.digest.nonce, nonce_buf);

            //pj_create_random_string(nonce_buf, sizeof(nonce_buf));
            //pj_strdup(rdata->tp_info.pool, &hdr->challenge.digest.opaque, &random);

            //hdr->challenge.digest.qop.slen = 0;

            pj_strdup2(rdata->tp_info.pool, &hdr->challenge.digest.realm, "123");
            //hdr->challenge.digest.stale = stale;

            pjsip_tx_data *p_tdata = nullptr;
            pjsip_response_addr res_addr;
            status = pjsip_endpt_create_response(mp_sip_endpt, rdata, 401, nullptr, &p_tdata);
            status = pjsip_get_response_addr(rdata->tp_info.pool, rdata, &res_addr);
            pjsip_msg_add_hdr(p_tdata->msg, (pjsip_hdr*)hdr);
            status = pjsip_endpt_send_response(mp_sip_endpt, &res_addr, p_tdata, nullptr, nullptr);
            if (PJ_SUCCESS != status)
            {
                LOG_ERROR_PJ("发送注册回应帧[401]失败:" << status);
                return PJ_FALSE;
            }
            return PJ_TRUE;
        }
        else
        {
            // 4
            auto str_date = ptime_to_register_date();
            pj_str_t n, v;
            pj_strdup2(rdata->tp_info.pool, &n, "Date");
            pj_strdup2(rdata->tp_info.pool, &v, str_date.c_str());
            auto hdr_date = pjsip_generic_string_hdr_create(rdata->tp_info.pool, &n, &v);
            pj_strdup2(rdata->tp_info.pool, &n, "Expires");
            pj_strdup2(rdata->tp_info.pool, &v, "3600");
            auto hdr_expires = pjsip_generic_string_hdr_create(rdata->tp_info.pool, &n, &v);

            pjsip_tx_data *p_tdata = nullptr;
            pjsip_response_addr res_addr;
            status = pjsip_endpt_create_response(mp_sip_endpt, rdata, 200, nullptr, &p_tdata);
            status = pjsip_get_response_addr(rdata->tp_info.pool, rdata, &res_addr);
            pjsip_msg_add_hdr(p_tdata->msg, (pjsip_hdr*)hdr_date);
            pjsip_msg_add_hdr(p_tdata->msg, (pjsip_hdr*)hdr_expires);
            
            status = pjsip_endpt_send_response(mp_sip_endpt, &res_addr, p_tdata, nullptr, nullptr);
            if (PJ_SUCCESS != status)
            {
                LOG_ERROR_PJ("发送注册回应帧[200]失败:" << status);
                return PJ_FALSE;
            }
            LOG_INFO_PJ("注册成功");
            return PJ_TRUE;
        }
    }
    return PJ_FALSE;
}

std::string server_sip::ptime_to_register_date(){
    try
    {
        auto time_current = boost::posix_time::second_clock::local_time();
        std::stringstream ss;
        char fill_char = '0';
        auto date = time_current.date();
        ss  << std::setw(4) << std::setfill(fill_char)<<static_cast<int>(date.year())<<"-";
        ss  << std::setw(2) << std::setfill(fill_char)<<static_cast<int>(date.month())<<"-";
        ss  << std::setw(2) << std::setfill(fill_char)<<static_cast<int>(date.day());
        ss << "T";
        auto td = time_current.time_of_day();
        ss  << std::setw(2) << std::setfill(fill_char)<< boost::date_time::absolute_value(td.hours()) << ":";
        ss  << std::setw(2) << std::setfill(fill_char)<< boost::date_time::absolute_value(td.minutes()) << ":";
        ss  << std::setw(2) << std::setfill(fill_char)<< boost::date_time::absolute_value(td.seconds());
        ss  << "." << std::setw(boost::posix_time::time_duration::num_fractional_digits())<<std::setw(3)<< std::setfill(fill_char)<< boost::date_time::absolute_value(td.fractional_seconds());
        return ss.str();
    }
    catch(const std::exception&)
    {
    }
    return "";
}

pj_bool_t server_sip::on_rx_response(pjsip_rx_data *rdata)
{
    LOG_DEBUG_PJ("on_rx_response");
    return PJ_FALSE;
}

pj_bool_t server_sip::on_tx_request(pjsip_tx_data *tdata)
{
    LOG_DEBUG_PJ("on_tx_request");
    return PJ_TRUE;
}

pj_bool_t server_sip::on_tx_response(pjsip_tx_data *tdata)
{
    LOG_DEBUG_PJ("on_tx_response");
    return PJ_TRUE;
}

void server_sip::on_tsx_state(pjsip_transaction *tsx, pjsip_event *event)
{
    LOG_DEBUG_PJ("on_tsx_state");
}

int server_sip::worker_thread(void *arg)
{
    LOG_INFO_PJ("工作线程开始");
    auto pparams = reinterpret_cast<std::pair<pjsip_endpoint *, pj_bool_t *> *>(arg);
    if (nullptr == pparams)
    {
        LOG_ERROR_PJ("工作线程参数错误");
        return -1;
    }
    while ((pparams->second))
    {
        pj_time_val timeout = {0, 500};
        pjsip_endpt_handle_events(pparams->first, &timeout);
    }
    LOG_INFO_PJ("工作线程结束");
    return 0;
}

int server_sip::decode_sdp(info_param_ptr &, const char **, const char **)
{
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
