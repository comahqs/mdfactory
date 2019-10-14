#include "server_sip.h"
#include "utility_tool.h"
#include "error_code.h"
#include <boost/format.hpp>
#include <sstream>
#include <pjsip/sip_auth_parser.h>
#include <pjsip/sip_endpoint.h>







#define SDP_RTPMAP_PS "96 PS/90000"
#define SDP_RTPMAP_MPEG4 "97 MPEG4/90000"
#define SDP_RTPMAP_H264 "98 H264/90000"
#define SDP_RTPMAP_ADD_ATT(N,V) {attr = (pjmedia_sdp_attr*)pj_pool_zalloc(mp_pool, sizeof(pjmedia_sdp_attr)); \
	attr->name = pj_strdup3(mp_pool, N); \
	attr->value = pj_strdup3(mp_pool, V); \
	m->attr[m->attr_count++] = attr; }

#define SDP_RTPMAP_ADD_OTHER(N,V) {attr = (pjmedia_sdp_attr*)pj_pool_zalloc(mp_pool, sizeof(pjmedia_sdp_attr)); \
	attr->name = pj_strdup3(mp_pool, N); \
	attr->value = pj_strdup3(mp_pool, V); \
	sdp->other[sdp->other_count++] = attr; }

#define SDP_S_PLAY "Play"
#define SDP_S_PLAY_BACK "Playback"
#define SDP_S_DOWNLOAD "Download"


#define KEY_PLAY "Play@"
#define KEY_CREATE(PRE,INDEX) (PRE#INDEX)

std::shared_ptr<server_sip> server_sip::s_instance = nullptr;
int server_sip::s_module_id = 0;

static module_media_ptr mp_media;

std::shared_ptr<server_sip> server_sip::get_instance() {
	if (!s_instance)
	{
		s_instance = std::shared_ptr<server_sip>(new server_sip());
	}
	return s_instance;
}

void server_sip::at_state_changed(pjsip_inv_session *inv, pjsip_event *e){
    LOG_DEBUG_PJ("请求状态更新");
	if (s_instance)
	{
		return s_instance->on_state_changed(inv, e);
	}
}

void server_sip::at_new_session(pjsip_inv_session *inv, pjsip_event *e){
    LOG_DEBUG_PJ("新请求连接");
	if (s_instance)
	{
		return s_instance->on_new_session(inv, e);
	}
}

void server_sip::at_tsx_state_changed(pjsip_inv_session *inv, pjsip_transaction *tsx, pjsip_event *e){
    LOG_DEBUG_PJ("事务状态更新");
	if (s_instance)
	{
		return s_instance->on_tsx_state_changed(inv, tsx, e);
	}
}

 void server_sip::at_media_update(pjsip_inv_session *inv, pj_status_t status){
    LOG_DEBUG_PJ("媒体信息更新");
	if (s_instance)
	{
		return s_instance->on_media_update(inv, status);
	}
 }

 void server_sip::at_send_ack(pjsip_inv_session *inv, pjsip_rx_data *rdata){
    LOG_DEBUG_PJ("发送ACK");
	if (s_instance)
	{
		return s_instance->on_send_ack(inv,rdata);
	}
 }

server_sip::server_sip()
{
	m_id = "34020000002000000001";
	m_ip = "192.168.2.2";
}

server_sip::~server_sip()
{
}

bool server_sip::start(const int& port)
{
	mp_media = std::make_shared<module_media>();
	mp_media->start();

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
    status = pjsip_endpt_create(&m_cp.factory, nullptr,
                                &mp_sip_endpt);
    if (PJ_SUCCESS != status)
    {
        LOG_ERROR_PJ("创建pj端点失败:" << status);
        return false;
    }

	pj_ioqueue_t* ioqueue = pjsip_endpt_get_ioqueue(mp_sip_endpt);
	status = pjmedia_endpt_create(&m_cp.factory, ioqueue, 0, &mp_media_endpt);
	if (PJ_SUCCESS != status)
	{
		LOG_ERROR_PJ("创建多媒体端点失败:"<<status);
		return false;
	}

	status = pjmedia_codec_g711_init(mp_media_endpt);
	if (PJ_SUCCESS != status)
	{
		LOG_ERROR_PJ("初始化G711库失败:" << status);
		return false;
	}

    /*
         * Add UDP transport, with hard-coded port
         */
    pj_sockaddr_in addr;

    addr.sin_family = pj_AF_INET();
    addr.sin_addr.s_addr = 0;
    addr.sin_port = pj_htons(static_cast<pj_uint16_t>(port));

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
	char tmp_str[128] = { 0 };
	sprintf(tmp_str, "server_sip");
	m_module.name.ptr = tmp_str;
	m_module.name.slen = strlen(tmp_str);
    m_module.id = -1;
    m_module.load = nullptr;
    m_module.unload = nullptr;
    m_module.start = nullptr;
    m_module.stop = nullptr;
    m_module.priority = PJSIP_MOD_PRIORITY_APPLICATION;
    m_module.on_rx_request = &server_sip::at_rx_request;
    m_module.on_rx_response = &server_sip::at_rx_response;
    m_module.on_tx_request = &server_sip::at_tx_request;
    m_module.on_tx_response = &server_sip::at_tx_response;
    m_module.on_tsx_state = &server_sip::at_tsx_state;

    status = pjsip_endpt_register_module(mp_sip_endpt, &m_module);
    if (status != PJ_SUCCESS)
    {
        LOG_ERROR_PJ("注册自定义模块失败:" << status);
        return false;
    }
	s_module_id = m_module.id;

    status = pjsip_100rel_init_module(mp_sip_endpt);
    if (status != PJ_SUCCESS)
    {
        LOG_ERROR_PJ("注册100rel模块失败:" << status);
        return false;
    }

    pj_bzero(&m_inv_callback, sizeof(m_inv_callback));
    m_inv_callback.on_state_changed = &server_sip::at_state_changed;
    m_inv_callback.on_new_session = &server_sip::at_new_session;
    m_inv_callback.on_tsx_state_changed = &server_sip::at_tsx_state_changed;
    m_inv_callback.on_media_update = &server_sip::at_media_update;
    m_inv_callback.on_send_ack = &at_send_ack;
    status = pjsip_inv_usage_init(mp_sip_endpt, &m_inv_callback);

    mp_pool = pjsip_endpt_create_pool(mp_sip_endpt, "server_sip", 10000, 10000);
    if (nullptr == mp_pool)
    {
        LOG_ERROR_PJ("创建内存池失败:" << status);
        return false;
    }

    m_flag = PJ_TRUE;
    status = pj_thread_create(mp_pool, "server_sip", server_sip::worker_thread, this, 0, 0, &mp_thread);
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

pj_bool_t server_sip::at_rx_request(pjsip_rx_data *rdata) {
	if (s_instance)
	{
		return s_instance->on_rx_request(rdata);
	}
	return PJ_FALSE;
}

pj_bool_t server_sip::at_rx_response(pjsip_rx_data *rdata) {
	if (s_instance)
	{
		return s_instance->on_rx_response(rdata);
	}
	return PJ_FALSE;
}

pj_status_t server_sip::at_tx_request(pjsip_tx_data *tdata) {
	if (s_instance)
	{
		return s_instance->on_tx_request(tdata);
	}
	return PJ_SUCCESS;
}

pj_status_t server_sip::at_tx_response(pjsip_tx_data *tdata) {
	if (s_instance)
	{
		return s_instance->on_tx_response(tdata);
	}
	return PJ_SUCCESS;
}

void server_sip::at_tsx_state(pjsip_transaction *tsx, pjsip_event *event) {
	if (s_instance)
	{
		return s_instance->on_tsx_state(tsx, event);
	}
}

pj_bool_t server_sip::on_rx_request(pjsip_rx_data *rdata)
{
    LOG_DEBUG_PJ("收到上行请求帧");
    pj_status_t status;
    if (pjsip_method_e::PJSIP_REGISTER_METHOD == rdata->msg_info.cseq->method.id)
    {
        // 注册与注销
        std::string name;
        // Expires为0表示注销
        auto hdr_expires = (pjsip_expires_hdr *)pjsip_msg_find_hdr(rdata->msg_info.msg, pjsip_hdr_e::PJSIP_H_EXPIRES, nullptr);
        if (nullptr == hdr_expires)
        {
            name = "未知";
        }
        else if (0 != hdr_expires->ivalue)
        {
            name = "注册";
        }
        else
        {
            name = "注销";
        }
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
            pjsip_msg_add_hdr(p_tdata->msg, (pjsip_hdr *)hdr);
            status = pjsip_endpt_send_response(mp_sip_endpt, &res_addr, p_tdata, nullptr, nullptr);
            if (PJ_SUCCESS != status)
            {
                LOG_ERROR_PJ("发送" << name << "回应帧[401]失败:" << status);
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
            pjsip_msg_add_hdr(p_tdata->msg, (pjsip_hdr *)hdr_date);
            pjsip_msg_add_hdr(p_tdata->msg, (pjsip_hdr *)hdr_expires);

            status = pjsip_endpt_send_response(mp_sip_endpt, &res_addr, p_tdata, nullptr, nullptr);
            if (PJ_SUCCESS != status)
            {
                LOG_ERROR_PJ("发送" << name << "回应帧[200]失败:" << status);
                return PJ_FALSE;
            }
            LOG_INFO_PJ(name << "成功");

			// 发送目录查询
			{
				pjsip_tx_data *p_tdata = nullptr;
				pjsip_method m;
				m.id = PJSIP_OTHER_METHOD;
				m.name = pj_strdup3(rdata->tp_info.pool, "MESSAGE");
				status = pjsip_endpt_create_request(mp_sip_endpt, &m, &pj_strdup3(rdata->tp_info.pool, "sip:34020000001320000001@192.168.2.64:5060"), &pj_strdup3(rdata->tp_info.pool, "sip:34020000002000000001@3402000000")
				    , &pj_strdup3(rdata->tp_info.pool, "sip:34020000001320000001@3402000000"), &pj_strdup3(rdata->tp_info.pool, "sip:34020000002000000001@192.168.2.2:5060"), nullptr, -1, nullptr, &p_tdata);

				p_tdata->msg->body = pjsip_msg_body_create(rdata->tp_info.pool, &pj_strdup3(rdata->tp_info.pool, "Application"), &pj_strdup3(rdata->tp_info.pool, "MANSCDP+xml")
					, &pj_strdup3(rdata->tp_info.pool, "<?xml version=\"1.0\"?>\r\n<Query><CmdType>Catalog</CmdType><SN>2</SN><DeviceID>34020000001320000001</DeviceID></Query>"));
				status = pjsip_endpt_send_request(mp_sip_endpt, p_tdata, -1, nullptr, nullptr);
				if (PJ_SUCCESS != status)
				{
				}
			}

            return PJ_TRUE;
        }
    }
    else if (is_equal("MESSAGE", rdata->msg_info.cseq->method.name))
    {
		auto tsx = pjsip_rdata_get_tsx(rdata);
        if (is_equal("Application", rdata->msg_info.ctype->media.type) && is_equal("MANSCDP+xml", rdata->msg_info.ctype->media.subtype))
        {
            // 解析XML
            auto proot = pj_xml_parse(rdata->tp_info.pool, reinterpret_cast<char *>(rdata->msg_info.msg->body->data), rdata->msg_info.msg->body->len);
            if (nullptr == proot)
            {
                LOG_ERROR_PJ("解析XML数据失败");
                return PJ_FALSE;
            }
            pj_str_t name;
            pj_strdup2(rdata->tp_info.pool, &name, "CmdType");
            auto pnode_cmd_type = pj_xml_find_node(proot, &name);
            if (nullptr == pnode_cmd_type)
            {
                LOG_ERROR_PJ("找不到节点[CmdType]");
                return PJ_FALSE;
            }
            if (0 == pj_strcmp2(&pnode_cmd_type->content, "Keepalive"))
            {
                // 心跳
                status = pjsip_endpt_respond_stateless(mp_sip_endpt, rdata, 200, nullptr, nullptr, nullptr);
                if (PJ_SUCCESS != status)
                {
                    LOG_ERROR_PJ("发送心跳回应帧失败:" << status);
                    return PJ_FALSE;
                }

				{
					static bool s_flag = false;
					if (!s_flag)
					{
						s_flag = true;
						start_play("34020000001320000001", "34020000001320000001", "192.168.2.64");
					}
				}
                return PJ_TRUE;
            }
            else if (0 == pj_strcmp2(&pnode_cmd_type->content, "Catalog"))
            {
				// 目录查询
				status = pjsip_endpt_respond_stateless(mp_sip_endpt, rdata, 200, nullptr, nullptr, nullptr);
				if (PJ_SUCCESS != status)
				{
					LOG_ERROR_PJ("发送目录查询回应帧失败:" << status);
					return PJ_FALSE;
				}
				return PJ_TRUE;
            }else{
                LOG_DEBUG_PJ("无法处理的命令:" << to_str(pnode_cmd_type->content));
            }
        }
    }
    return PJ_FALSE;
}

void server_sip::start_dlg_device_search(pjsip_rx_data *rdata)
{
    auto &pool = rdata->tp_info.pool;
    auto local_uri = pj_strdup3(pool, "sip:abc@192.168.2.2:5060");
    auto remote_uri = pj_strdup3(pool, "sip:1@192.168.2.64:5060");
    pjsip_dialog *pdlg = nullptr;
    pj_status_t status;
    status = pjsip_dlg_create_uac(pjsip_ua_instance(), &local_uri, nullptr, &remote_uri, nullptr, &pdlg);
    if (PJ_SUCCESS != status)
    {
        LOG_ERROR_PJ("创建uac失败:" << error_to_str(status) << "; 错误代码:" << status);
    }
    pjsip_dlg_inc_lock(pdlg);
    //status = pjsip_dlg_add_usage(pdlg, &m_module, nullptr);
    if (PJ_SUCCESS != status)
    {
        LOG_ERROR_PJ("添加自定义模块失败:" << error_to_str(status) << "; 错误代码:" << status);
    }
    else
    {
        pjsip_inv_session *p_inv = nullptr;
        status = pjsip_inv_create_uac(pdlg, nullptr, 0, &p_inv);
		if (PJ_SUCCESS != status)
		{
			LOG_ERROR_PJ("创建UAC失败:" << error_to_str(status) << "; 错误代码:" << status);
		}else {
			pjsip_tx_data *tdata = nullptr;
			status = pjsip_inv_invite(p_inv, &tdata);
			if (PJ_SUCCESS != status)
			{
				LOG_ERROR_PJ("创建UAC失败:" << error_to_str(status) << "; 错误代码:" << status);
			}else {
				status = pjsip_inv_send_msg(p_inv, tdata);
				if (PJ_SUCCESS != status)
				{
					LOG_ERROR_PJ("创建UAC失败:" << error_to_str(status) << "; 错误代码:" << status);
				}else {
				}
			}
		}
    }

    pjsip_dlg_dec_lock(pdlg);
}

std::string server_sip::error_to_str(const pj_status_t &status)
{
    char str_tmp[128] = {0};
    pjsip_strerror(status, str_tmp, 127);
    return std::string(str_tmp);
}

bool server_sip::is_equal(const char *p1, const pj_str_t &s2)
{
    if (nullptr == p1 || nullptr == s2.ptr)
    {
        return false;
    }
    return 0 == memcmp(p1, s2.ptr, std::min<std::size_t>(sizeof(p1), s2.slen));
}

std::string server_sip::to_str(const pj_str_t &s)
{
    if (nullptr == s.ptr || 0 == s.slen)
    {
        return "";
    }
    return std::string(s.ptr, s.slen);
}

std::string server_sip::ptime_to_register_date()
{
    try
    {
        auto time_current = boost::posix_time::second_clock::local_time();
        std::stringstream ss;
        char fill_char = '0';
        auto date = time_current.date();
        ss << std::setw(4) << std::setfill(fill_char) << static_cast<int>(date.year()) << "-";
        ss << std::setw(2) << std::setfill(fill_char) << static_cast<int>(date.month()) << "-";
        ss << std::setw(2) << std::setfill(fill_char) << static_cast<int>(date.day());
        ss << "T";
        auto td = time_current.time_of_day();
        ss << std::setw(2) << std::setfill(fill_char) << boost::date_time::absolute_value(td.hours()) << ":";
        ss << std::setw(2) << std::setfill(fill_char) << boost::date_time::absolute_value(td.minutes()) << ":";
        ss << std::setw(2) << std::setfill(fill_char) << boost::date_time::absolute_value(td.seconds());
        ss << "." << std::setw(boost::posix_time::time_duration::num_fractional_digits()) << std::setw(3) << std::setfill(fill_char) << boost::date_time::absolute_value(td.fractional_seconds());
        return ss.str();
    }
    catch (const std::exception &)
    {
    }
    return "";
}

pj_bool_t server_sip::on_rx_response(pjsip_rx_data *rdata)
{
    LOG_DEBUG_PJ("收到上行回应帧");
	auto pdlg = pjsip_rdata_get_dlg(rdata);
	if (nullptr == pdlg)
	{
		return PJ_FALSE;
	}
	pj_status_t status;
	if (pjsip_method_e::PJSIP_OTHER_METHOD == rdata->msg_info.cseq->method.id && 0 == pj_strcmp2(&rdata->msg_info.cseq->method.name, "OK")) {
		std::string key;
		if (!to_key(key, rdata->msg_info.msg))
		{
			return PJ_FALSE;
		}
		auto iter = m_dlgs.find(key);
		if (m_dlgs.end() == iter)
		{
			return PJ_FALSE;
		}
		auto pinfo = iter->second;
		if (KEY_CREATE(KEY_PLAY,3) == pinfo->step)
		{
			// 获取设备返回的SDP信息

			// 建立RTP

			// 发送ACK


		}
	}
    return PJ_FALSE;
}

pj_status_t server_sip::on_tx_request(pjsip_tx_data *tdata)
{
    LOG_DEBUG_PJ("发送下行请求帧");
    return PJ_SUCCESS;
}

pj_status_t server_sip::on_tx_response(pjsip_tx_data *tdata)
{
    LOG_DEBUG_PJ("发送下行回应帧");
    return PJ_SUCCESS;
}

void server_sip::on_tsx_state(pjsip_transaction *tsx, pjsip_event *event)
{
    LOG_DEBUG_PJ("事务状态改变");
}

int server_sip::worker_thread(void *arg)
{
    LOG_INFO_PJ("工作线程开始");
    auto psip = reinterpret_cast<server_sip *>(arg);
    if (nullptr == psip)
    {
        LOG_ERROR_PJ("工作线程参数错误");
        return -1;
    }
    while (psip->m_flag)
    {
        pj_time_val timeout = {0, 1};
        pjsip_endpt_handle_events(psip->mp_sip_endpt, &timeout);
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

bool server_sip::start_play(const std::string& id_channel, const std::string& id_device, const std::string& ip) {
	// 确定目标设备是否已经上线

	// 创建会话
	auto uri_src = pj_strdup3(mp_pool, (boost::format("sip:%s@%s") % m_id % m_id.substr(0, 10)).str().c_str());
	auto contact_src = pj_strdup3(mp_pool, (boost::format("sip:%s@%s") % m_id % m_ip).str().c_str());
	auto uri_desc = pj_strdup3(mp_pool, (boost::format("sip:%s@%s") % id_device % id_device.substr(0, 10)).str().c_str());
	auto contact_desc = pj_strdup3(mp_pool, (boost::format("sip:%s@%s") % id_device % ip).str().c_str());

	pjsip_dialog *pdlg = nullptr;
	pj_status_t status;
	status = pjsip_dlg_create_uac(pjsip_ua_instance(), &uri_src, &contact_src, &uri_desc, &contact_desc, &pdlg);
	if (PJ_SUCCESS != status)
	{
		LOG_ERROR_PJ("创建uac失败:" << error_to_str(status) << "; 错误代码:" << status);
		return false;
	}
	pjsip_dlg_inc_lock(pdlg);
	//status = pjsip_dlg_add_usage(pdlg, &m_module, nullptr);
	if (PJ_SUCCESS != status)
	{
		LOG_ERROR_PJ("添加自定义模块失败:" << error_to_str(status) << "; 错误代码:" << status);
		return false;
	}

	// 创建SDP信息
	pjmedia_sdp_session *sdp = (pjmedia_sdp_session*)pj_pool_zalloc(mp_pool, sizeof(pjmedia_sdp_session));
	sdp->origin.id = 0;
	sdp->origin.user = pj_strdup3(mp_pool, id_channel.c_str());
	sdp->origin.version = 0;
	sdp->origin.net_type = pj_str("IN");
	sdp->origin.addr_type = pj_str("IP4");
	sdp->origin.addr = pj_strdup3(mp_pool, m_ip.c_str());
	// 1-实时； 2-回放；3-下载
	sdp->name = pj_strdup3(mp_pool, SDP_S_PLAY);

	sdp->conn = (pjmedia_sdp_conn*)pj_pool_zalloc(mp_pool, sizeof(pjmedia_sdp_conn));
	sdp->conn->net_type = pj_str("IN");
	sdp->conn->addr_type = pj_str("IP4");
	sdp->conn->addr = pj_strdup3(mp_pool, m_ip.c_str());
	// start和stop都为0表示实时流
	sdp->time.start = 0;
	sdp->time.stop = 0;
	sdp->attr_count = 0;

	sdp->media_count = 1;
	pjmedia_sdp_media *m = (pjmedia_sdp_media*)pj_pool_zalloc(mp_pool, sizeof(pjmedia_sdp_media));
	sdp->media[0] = m;
	// video表示是视频流，包括视频和音频
	m->desc.media = pj_str("video");
	m->desc.port = get_rtp_port();
	m->desc.port_count = 1;
	m->desc.transport = pj_strdup3(mp_pool, "RTP/AVP");
	// 3个视频格式
	m->desc.fmt_count = 3;
	m->attr_count = 0;

	pjmedia_sdp_attr *attr = (pjmedia_sdp_attr*)pj_pool_zalloc(mp_pool, sizeof(pjmedia_sdp_attr));
	attr->name = pj_strdup3(mp_pool, "recvonly");
	m->attr[m->attr_count++] = attr;

	// 96-PS格式；97-MPEG4格式；98-H264格式  默认为98
	int format = 98;
	if (96 == format)
	{
		m->desc.fmt[0] = pj_str("96");
		m->desc.fmt[1] = pj_str("98");
		m->desc.fmt[2] = pj_str("97");
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_PS);
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_H264);
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_MPEG4);
	}else if (97 == format)
	{
		m->desc.fmt[0] = pj_str("97");
		m->desc.fmt[1] = pj_str("98");
		m->desc.fmt[2] = pj_str("96");
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_MPEG4);
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_H264);
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_PS);
	}else if (98 == format)
	{
		m->desc.fmt[0] = pj_str("98");
		m->desc.fmt[1] = pj_str("96");
		m->desc.fmt[2] = pj_str("97");
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_H264);
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_PS);
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_MPEG4);
	}
	else {
		m->desc.fmt[0] = pj_str("98");
		m->desc.fmt[1] = pj_str("96");
		m->desc.fmt[2] = pj_str("97");
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_H264);
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_PS);
		SDP_RTPMAP_ADD_ATT("rtpmap", SDP_RTPMAP_MPEG4);
	}

	SDP_RTPMAP_ADD_OTHER("y", get_sdp_y(sdp->name, id_device).c_str());

	pjsip_inv_session *p_inv = nullptr;
	status = pjsip_inv_create_uac(pdlg, sdp, 0, &p_inv);
	if (PJ_SUCCESS != status) {
		LOG_ERROR_PJ("创建 [inv] 失败:" << error_to_str(status) << "; 错误代码:" << status);
		return false;
	}
	pjsip_tx_data *tdata = nullptr;
	status = pjsip_inv_invite(p_inv, &tdata);
	if (PJ_SUCCESS != status) {
		LOG_ERROR_PJ("初始化 [inv] 失败:" << error_to_str(status) << "; 错误代码:" << status);
		return false;
	}

	// 修改INVITE的目标地址为通道地址
	pj_str_t target;
	pj_strdup2_with_null(tdata->pool, &target, (boost::format("sip:%s@%s") % id_channel % ip).str().c_str());
	tdata->msg->line.req.uri = pjsip_parse_uri(tdata->pool, target.ptr, target.slen, 0);

	auto phdr_via = (pjsip_via_hdr*)pjsip_msg_find_hdr(tdata->msg, pjsip_hdr_e::PJSIP_H_VIA, nullptr);
	if (nullptr != phdr_via)
	{
		phdr_via->sent_by.host = pj_strdup3(mp_pool, ip.c_str());
		phdr_via->sent_by.port = 5060;
	}

	auto n = pj_strdup3(mp_pool, "Subject");
	auto v = pj_strdup3(mp_pool, (boost::format("%s:%d,%s:%d") % id_device % 1 % m_id % 1).str().c_str());
	pjsip_generic_string_hdr* hdr = pjsip_generic_string_hdr_create(mp_pool, &n, &v);
	pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)hdr);

	status = pjsip_inv_send_msg(p_inv, tdata);
	if (PJ_SUCCESS != status) {
		LOG_ERROR_PJ("发送 [inv] 失败:" << error_to_str(status) << "; 错误代码:" << status);
		return false;
	}

	auto pinfo = std::make_shared<info_dlg>();
	pinfo->pdlg = pdlg;
	pinfo->pinv = p_inv;
	pinfo->pinv->mod_data[s_module_id] = pinfo.get();
	pinfo->step = KEY_CREATE(KEY_PLAY,3);
	pinfo->local_port = m->desc.port;
	std::string key;
	if (!to_key(key, tdata->msg))
	{
		return false;
	}
	m_dlgs.insert(std::make_pair(key, pinfo));
	return true;
}

bool server_sip::to_key(std::string& key, pjsip_msg* pmsg) {
	auto phdr_via = (pjsip_via_hdr*)pjsip_msg_find_hdr(pmsg, pjsip_hdr_e::PJSIP_H_VIA, nullptr);
	if (nullptr == phdr_via)
	{
		LOG_ERROR_PJ("发送数据找不到对应 [Via]");
		return false;
	}
	key = std::string(phdr_via->branch_param.ptr, phdr_via->branch_param.slen);
	return true;
}

int server_sip::get_rtp_port() {
	static std::atomic_int s_port(2000);

	// rtp端口需要占用两个端口，这里需要步进2
	s_port += 2;
	return s_port;
}

std::string server_sip::get_sdp_y(const pj_str_t& name, const std::string& desc_id_device) {
	static std::atomic_int s_seq(1);

	auto type = 0;
	if (0 == pj_strcmp2(&name, SDP_S_PLAY))
	{
		type = 0;
	}else if (0 == pj_strcmp2(&name, SDP_S_PLAY_BACK)){
		type = 1;
	}
	else {
		type = 1;
	}
	return (boost::format("%1d%s%04d") % type % desc_id_device.substr(3, 5) % s_seq++).str();
}

info_dlg_ptr server_sip::find_info(const pjsip_msg* pmsg) {
	if (nullptr == pmsg)
	{
		return info_dlg_ptr();
	}
	auto phdr_via = (pjsip_via_hdr*)pjsip_msg_find_hdr(pmsg, pjsip_hdr_e::PJSIP_H_VIA, nullptr);
	if (nullptr == phdr_via)
	{
		LOG_ERROR_PJ("找不到对应 [Via]");
		return info_dlg_ptr();
	}
	auto key = std::string(phdr_via->branch_param.ptr, phdr_via->branch_param.slen);
	auto iter = m_dlgs.find(key);
	if (m_dlgs.end() == iter)
	{
		LOG_ERROR_PJ("找不到对应的信息，KEY:"<<key);
		return info_dlg_ptr();
	}
	return iter->second;
}

void server_sip::on_send_ack(pjsip_inv_session *inv, pjsip_rx_data *rdata) {
	info_dlg *pinfo = reinterpret_cast<info_dlg*>(inv->mod_data[s_module_id]);
	pjsip_tx_data *tdata;
	pjsip_inv_create_ack(pinfo->pinv, rdata->msg_info.cseq->cseq, &tdata);

	/** @note 置dlg传输选项, 此处必须要设置。因为使用tcp方式建立sip会话时，如果不设置
	*   dlg传输选项，invite会话在发送ack、bye等命令时，会新建一个连接来处理并且新建的
	*   连接是udp连接
	*   @note 这里如果不设置，那么invite会话在发送ack、bye等命令，只能命令拼接完成后，
	*   改由直接endpoint发送，但这样的话需要注意via头、cseq头的取值问题，并且endpoint
	*   发送时，需要在此处获取会话地址，获取方式参见pjsip_get_response_addr
	**/
	pjsip_tpselector tp_sel;
	tp_sel.type = PJSIP_TPSELECTOR_TRANSPORT;
	tp_sel.u.transport = pinfo->pinv->invite_tsx->transport;
	pjsip_dlg_set_transport(pinfo->pdlg, &tp_sel);
	pjsip_inv_send_msg(pinfo->pinv, tdata);
}
void server_sip::on_media_update(pjsip_inv_session *inv, pj_status_t status) {
	if (nullptr == inv) {
		LOG_ERROR_PJ("无效的INVITE");
		return;
	}


#define CLOSE_INVITE(CODE,MSG) {pjsip_inv_end_session(inv, CODE, nullptr, &tdata); \
	pjsip_inv_send_msg(pinfo->pinv, tdata); \
    LOG_ERROR_PJ(MSG<<"; 错误内容:"<< error_to_str(status) << "; 错误代码:" << status);}

	pjsip_tx_data *tdata;
	auto pinfo = find_info(inv->invite_req->msg);
	if (nullptr == pinfo)
	{
		LOG_ERROR_PJ("找不到对应的INVITE");
		return;
	}
	// 获取sdp描述
	const pjmedia_sdp_session *local_sdp, *remote_sdp;
	pj_status_t state = pjmedia_sdp_neg_get_active_local(inv->neg, &local_sdp);
	if (state != PJ_SUCCESS)
	{
		CLOSE_INVITE(PJSIP_SC_UNSUPPORTED_MEDIA_TYPE, "获取本地SDP信息失败");
		return;
	}
	state = pjmedia_sdp_neg_get_active_remote(inv->neg, &remote_sdp);
	if (state != PJ_SUCCESS)
	{
		CLOSE_INVITE(PJSIP_SC_UNSUPPORTED_MEDIA_TYPE, "获取远端SDP信息失败");
		return;
	}

	// 格式、协议等check
	if (remote_sdp->media_count <= 0 || nullptr == remote_sdp->media[remote_sdp->media_count - 1])
	{
		CLOSE_INVITE(PJSIP_SC_FORBIDDEN, "远端SDP多媒体信息为空");
		return;
	}

	if (remote_sdp->media[remote_sdp->media_count - 1]->desc.fmt_count <= 0)
	{
		CLOSE_INVITE(PJSIP_SC_FORBIDDEN, "远端多媒体格式为空");
		return;
	}
	pj_str_t TransType = remote_sdp->media[remote_sdp->media_count - 1]->desc.transport;
	if (0 != pj_strcmp2(&TransType, "RTP/AVP"))
	{
		CLOSE_INVITE(PJSIP_SC_FORBIDDEN, "远端多媒体传输类型错误:"<<std::string(TransType.ptr, TransType.slen));
		return;
	}

	// 媒体信息获取
	std::string format(remote_sdp->media[remote_sdp->media_count - 1]->desc.fmt[0].ptr, remote_sdp->media[remote_sdp->media_count - 1]->desc.fmt[0].slen);
	LOG_INFO_PJ("发送端媒体格式:" << format << "; 开始时间:" << remote_sdp->time.start << "; 结束时间:"<< remote_sdp->time.stop);

	// 创建rtp会话,设置会话地址、断开等
	std::string data;
	if (!find_other_from_sdp(data, "y", remote_sdp) || 10 != data.size())
	{
		CLOSE_INVITE(PJSIP_SC_FORBIDDEN, "远端SDP找不到其他参数或参数错误[y]:"<<data);
		return;
	}
	pj_uint32_t ssrc = atol(data.c_str());
	state = pjmedia_rtp_session_init(&pinfo->session, atoi(format.c_str()), ssrc);
	if (state != PJ_SUCCESS)
	{
		CLOSE_INVITE(PJSIP_SC_FORBIDDEN, "初始化Session失败");
		return;
	}
	pjmedia_sdp_media *m = remote_sdp->media[remote_sdp->media_count - 1];
	int nport = m->desc.port;
	pjmedia_sdp_conn *c = remote_sdp->conn;
	std::string ip(c->addr.ptr, c->addr.slen);
	pj_sockaddr_in remote_addr;
	pj_str_t tmpPjStr = pj_strdup3(inv->pool, ip.c_str());
	state = pj_sockaddr_in_init(&remote_addr, &tmpPjStr, nport);
	if (status != PJ_SUCCESS)
	{
		CLOSE_INVITE(PJSIP_SC_FORBIDDEN, "初始化远端地址失败");
		return;
	}

	auto rtpName = (boost::format("SIPRTP:%d") % pinfo->local_port).str();
	state = pjmedia_transport_udp_create(mp_media_endpt, rtpName.c_str(), pinfo->local_port, 0, &pinfo->ptransport);
	if (state != PJ_SUCCESS)
	{
		CLOSE_INVITE(PJSIP_SC_UNSUPPORTED_MEDIA_TYPE, "创建本地RTP传输端口失败");
		return;
	}
	// 根据选定的格式设置要获取的流类型
	if ("96" == format)
	{
		state = pjmedia_transport_attach(pinfo->ptransport, pinfo.get(), &remote_addr, nullptr, sizeof(pj_sockaddr_in), &server_sip::at_rx_rtp_ps, nullptr);
	}
	else
	{
		state = pjmedia_transport_attach(pinfo->ptransport, pinfo.get(), &remote_addr, nullptr, sizeof(pj_sockaddr_in), &server_sip::at_rx_rtp_h264, nullptr);
	}
	if (state != PJ_SUCCESS)
	{
		LOG_ERROR_PJ("绑定RTP回调失败:" << error_to_str(status) << "; 错误代码:" << status);
		// 传输断开
		pjmedia_transport_detach(pinfo->ptransport, this);
		pjmedia_transport_close(pinfo->ptransport);
		pjsip_inv_end_session(inv, PJSIP_SC_FORBIDDEN, nullptr, &tdata);
		pjsip_inv_send_msg(pinfo->pinv, tdata);
		return;
	}

	state = pjmedia_transport_media_start(pinfo->ptransport, nullptr, nullptr, nullptr, 0);
	if (state != PJ_SUCCESS)
	{
		CLOSE_INVITE(PJSIP_SC_UNSUPPORTED_MEDIA_TYPE, "开启RTP失败");
		return;
	}
}
void server_sip::on_tsx_state_changed(pjsip_inv_session *inv, pjsip_transaction *tsx, pjsip_event *e) {
	info_dlg *pinfo = reinterpret_cast<info_dlg*>(inv->mod_data[s_module_id]);
	// 回放的message通知
	if (PJSIP_EVENT_RX_MSG == e->body.tsx_state.type
		&& NULL != e->body.tsx_state.src.rdata
		&& NULL != e->body.tsx_state.tsx
		&&PJSIP_TSX_STATE_TRYING == e->body.tsx_state.tsx->state
		&& PJSIP_OTHER_METHOD == e->body.tsx_state.tsx->method.id
		&& 0 == pj_strcmp2(&e->body.tsx_state.tsx->method.name, "MESSAGE")
		&& 0 == e->body.tsx_state.tsx->status_code)
	{
		pjsip_tx_data *tdata;
		pj_status_t status = pjsip_dlg_create_response(pinfo->pdlg, e->body.rx_msg.rdata, 200, nullptr, &tdata);
		if (PJ_SUCCESS != status)
		{
			LOG_WARN_PJ("创建回应包失败");
		}
		else
		{
			status = pjsip_dlg_send_response(pinfo->pdlg, tsx, tdata);
			if (PJ_SUCCESS != status) {
				LOG_WARN_PJ("发送回应包失败");
			}
		}
		stop_stream(pinfo);
	}
}
void server_sip::on_new_session(pjsip_inv_session *inv, pjsip_event *e) {
}
void server_sip::on_state_changed(pjsip_inv_session *inv, pjsip_event *e) {
}

bool server_sip::find_other_from_sdp(std::string& v, const std::string& name, const pjmedia_sdp_session *sdp) {
	if (nullptr == sdp)
	{
		return false;
	}
	for (int i = 0; i < sdp->other_count; ++i)
	{
		if (0 == pj_strcmp2(&sdp->other[i]->name, name.c_str()))
		{
			v = std::string(sdp->other[i]->value.ptr, sdp->other[i]->value.slen);
			return true;
		}
	}
	return false;
}

void server_sip::at_rx_rtp_ps(void *user_data, void *pkt, pj_ssize_t size) {
	if (nullptr == pkt || 0 >= size)
	{
		return;
	}
	auto pinfo = reinterpret_cast<info_dlg*>(user_data);
	if (nullptr == pinfo)
	{
		return;
	}

	const pjmedia_rtp_hdr *hdr;
	const void *payload;
	unsigned payload_len;

	// RTP 数据解析
	pj_status_t status = pjmedia_rtp_decode_rtp(&pinfo->session, pkt, (int)size, &hdr, &payload, &payload_len);
	if (status != PJ_SUCCESS)
	{
		LOG_ERROR_PJ("多媒体数据解析失败");
		return;
	}
	static int sindex = 0;
	int seq = (((hdr->seq & 0xFF) << 8) | ((hdr->seq >> 8) & 0xFF));
	//LOG_DEBUG_PJ("SEQ:" << seq << ";  time:" << hdr->ts << "; index:" << sindex++ << "; 数据包:"<< size);
	if (seq != sindex)
	{
		LOG_DEBUG_PJ("SEQ:" << seq << ";  time:" << hdr->ts << "; index:" << sindex++ << "; 数据包:" << size);
	}
	sindex++;

	// 数据在payload
	decode_ps(payload, payload_len);

	// rtp会话信息更新
	pjmedia_rtp_session_update(&pinfo->session, hdr, nullptr);
}

void server_sip::at_rx_rtp_h264(void *user_data, void *pkt, pj_ssize_t size) {
	if (nullptr == pkt || 0 >= size)
	{
		return;
	}
	auto pinfo = reinterpret_cast<info_dlg*>(user_data);
	if (nullptr == pinfo)
	{
		return;
	}

	const pjmedia_rtp_hdr *hdr;
	const void *payload;
	unsigned payload_len;

	// RTP 数据解析
	pj_status_t status = pjmedia_rtp_decode_rtp(&pinfo->session, pkt, (int)size, &hdr, &payload, &payload_len);
	if (status != PJ_SUCCESS)
	{
		LOG_ERROR_PJ("多媒体数据解析失败");
		return;
	}

	// 数据在payload
	mp_media->write(reinterpret_cast<const unsigned char*>(payload), payload_len);

	// rtp会话信息更新
	pjmedia_rtp_session_update(&pinfo->session, hdr, nullptr);
}

void server_sip::decode_ps(const void *payload, unsigned payload_len) {

#define CHECK_DATA(D0,D1,D2,D3,PBUFFER) (D0==*(PBUFFER+0) && D1 ==*(PBUFFER+1) && D2 ==*(PBUFFER+2) && D3==*(PBUFFER+3))
#define CHECK_LEN(MIN) {if (MIN > len){return;}}
#define GET_LEN_2(PBUFFER) ((((*(PBUFFER))<<8) | (*(PBUFFER+1))) & 0xFFFF)

	static int s_last_offset = 0;

	auto pbuffer = reinterpret_cast<const unsigned char*>(payload);
	int len = payload_len;
	if (0 < s_last_offset)
	{
		//LOG_DEBUG_PJ("还需:" << s_last_offset << "; 输入:" << len << "; 差额:"<<(s_last_offset - len));
		if (s_last_offset < len)
		{
			// 够了，还有剩余
			mp_media->write(pbuffer, s_last_offset);
			len -= s_last_offset;
			pbuffer += s_last_offset;
			s_last_offset = 0;

			//LOG_DEBUG_PJ("开头:"<<(boost::format("%02X%02X%02X%02X%02X") % static_cast<int>(*(pbuffer + 0)) % static_cast<int>(*(pbuffer + 1)) % static_cast<int>(*(pbuffer + 2)) % static_cast<int>(*(pbuffer + 3)) % static_cast<int>(*(pbuffer + 4))).str());
		}
		else {
			// 接收的数据还不够
			mp_media->write(pbuffer, len);
			s_last_offset -= len;
			return;
		}
	}

	

	unsigned char tmp_frame[2048] = { 0 };
	std::size_t len_frame = 0;
	std::size_t frame_offset = 0;

	while (4 <= len)
	{
		if (CHECK_DATA(0x00, 0x00, 0x01, 0xBA, pbuffer))
		{
			// PS头至少14字节，第14字节的后3位定义了扩展长度
			if (14 > len)
			{
				return;
			}
			std::size_t len_ps_header = (*(pbuffer + 13) & 0x07);
			len = len - 14 - len_ps_header;
			pbuffer = pbuffer + 14 + len_ps_header;
		}else if (CHECK_DATA(0x00, 0x00, 0x01, 0xE0, pbuffer))
		{
			// PES包
			// 至少9字节
			CHECK_LEN(9);
			// PES包长度
			int len_pes = GET_LEN_2(pbuffer + 4);
			int len_pes_stuffing = *(pbuffer + 8);
			int len_data = len_pes - 2 - 1 - len_pes_stuffing;
			const unsigned char* pdata = pbuffer + 9 + len_pes_stuffing;
			len = len - 9 - len_pes_stuffing;
			pbuffer = pbuffer + 6 + len_pes;

			if (0 < len_data)
			{
				if (len_data <= len)
				{
					memcpy(tmp_frame + frame_offset, pdata, len_data);
					frame_offset += len_data;
					len -= len_data;
					//mp_media->write(pdata, len_data);
				}
				else {
					//mp_media->write(pdata, len);
					memcpy(tmp_frame + frame_offset, pdata, len);
					frame_offset += len;
					s_last_offset = len_data - len;
					len = 0;
				}
			}
		}
		else if (CHECK_DATA(0x00, 0x00, 0x01, 0xBC, pbuffer))
		{
			// I帧，解析Stream Map
			CHECK_LEN(6);

			std::size_t len_stream = GET_LEN_2(pbuffer + 4);
			len = len - 6 - len_stream;
			pbuffer = pbuffer + 6 + len_stream;
		}
		else if (CHECK_DATA(0x00, 0x00, 0x01, 0xC0, pbuffer))
		{
			// 音频数据
			CHECK_LEN(6);

			std::size_t len_stream = GET_LEN_2(pbuffer + 4);
			len = len - 6 - len_stream;
			pbuffer = pbuffer + 6 + len_stream;
			/*
			auto pdata = pbuffer + 6;
			auto len_data = len_stream;
			len = len - 6;
			pbuffer = pbuffer + 6 + len_stream;

			if (0 < len_data)
			{
				if (len_data <= len)
				{
					memcpy(tmp_frame + frame_offset, pdata, len_data);
					frame_offset += len_data;
					len -= len_data;
					//mp_media->write(pdata, len_data);
				}
				else {
					//mp_media->write(pdata, len);
					memcpy(tmp_frame + frame_offset, pdata, len);
					frame_offset += len;
					s_last_offset = len_data - len;
					len = 0;
				}
			}
			*/
		}
		else if (CHECK_DATA(0x00, 0x00, 0x01, 0xBD, pbuffer))
		{
			// 私有数据
			CHECK_LEN(6);

			std::size_t len_stream = GET_LEN_2(pbuffer + 4);
			len = len - 6 - len_stream;
			pbuffer = pbuffer + 6 + len_stream;
		}
		else if (CHECK_DATA(0x00, 0x00, 0x01, 0xBB, pbuffer))
		{
			// 标题数据
			CHECK_LEN(6);

			std::size_t len_stream = GET_LEN_2(pbuffer + 4);
			len = len - 6 - len_stream;
			pbuffer = pbuffer + 6 + len_stream;
		}
		else {
			//LOG_ERROR_PJ("无法识别的流类型:" << *(pbuffer + 3));
			return;
		}
	}

	if (0 < frame_offset)
	{
		mp_media->write(tmp_frame, frame_offset);
	}
}

void server_sip::on_rx_rtp_ps(void *user_data, void *pkt, pj_ssize_t size) {
	
}
void server_sip::on_rx_rtp_h264(void *user_data, void *pkt, pj_ssize_t size) {
}

void server_sip::stop_stream(info_dlg *pinfo) {
	pj_status_t status;
	pjsip_tx_data *tdata;
	status = pjsip_inv_end_session(pinfo->pinv, PJSIP_SC_DECLINE, nullptr, &tdata);
	if (status != PJ_SUCCESS || NULL == tdata)
	{
		LOG_ERROR_PJ("创建结束帧失败");
		return ;
	}

	status = pjsip_inv_send_msg(pinfo->pinv, tdata);
	if (status != PJ_SUCCESS)
	{
		LOG_ERROR_PJ("发送结束帧失败");
		return;
	}
	// 传输断开
	pjmedia_transport_detach(pinfo->ptransport, this);
	pjmedia_transport_close(pinfo->ptransport);
}