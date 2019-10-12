#ifndef SERVER_SIP_H
#define SERVER_SIP_H

#include "plugin.h"
#include <map>
#include <vector>
#include "module_sip.h"
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <pjsip_ua.h>
#include <pjmedia.h>
#include "module_media.h"

class info_dlg {
public:
	pjsip_dialog *pdlg = nullptr;
	pjsip_inv_session *pinv = nullptr;
	struct pjmedia_rtp_session session;
	struct pjmedia_transport *ptransport;
	int local_port = 0;
	std::string step;
};
typedef std::shared_ptr<info_dlg> info_dlg_ptr;

class server_sip
{
public:
    virtual ~server_sip();
    virtual bool start(const int& port);
    virtual void stop();
	virtual bool start_play(const std::string& id_channel, const std::string& id_device, const std::string& ip);

	static std::shared_ptr<server_sip> get_instance();
protected:
    static pj_bool_t at_rx_request(pjsip_rx_data *rdata);
    static pj_bool_t at_rx_response(pjsip_rx_data *rdata);
    static pj_status_t at_tx_request(pjsip_tx_data *tdata);
    static pj_status_t at_tx_response(pjsip_tx_data *tdata);
	static void at_tsx_state(pjsip_transaction *tsx, pjsip_event *event);
	static int worker_thread(void *arg);

	static void at_send_ack(pjsip_inv_session *inv, pjsip_rx_data *rdata);
	static void at_media_update(pjsip_inv_session *inv, pj_status_t status);
	static void at_tsx_state_changed(pjsip_inv_session *inv, pjsip_transaction *tsx, pjsip_event *e);
	static void at_new_session(pjsip_inv_session *inv, pjsip_event *e);
	static void at_state_changed(pjsip_inv_session *inv, pjsip_event *e);

	static void at_rx_rtp_ps(void *user_data, void *pkt, pj_ssize_t size);
	static void at_rx_rtp_h264(void *user_data, void *pkt, pj_ssize_t size);
	static void decode_ps(const void *payload, unsigned payload_len);

	server_sip();
	pj_bool_t on_rx_request(pjsip_rx_data *rdata);
	pj_bool_t on_rx_response(pjsip_rx_data *rdata);
	pj_status_t on_tx_request(pjsip_tx_data *tdata);
	pj_status_t on_tx_response(pjsip_tx_data *tdata);
	void on_tsx_state(pjsip_transaction *tsx, pjsip_event *event);

	void on_send_ack(pjsip_inv_session *inv, pjsip_rx_data *rdata);
	void on_media_update(pjsip_inv_session *inv, pj_status_t status);
	void on_tsx_state_changed(pjsip_inv_session *inv, pjsip_transaction *tsx, pjsip_event *e);
	void on_new_session(pjsip_inv_session *inv, pjsip_event *e);
	void on_state_changed(pjsip_inv_session *inv, pjsip_event *e);

	void on_rx_rtp_ps(void *user_data, void *pkt, pj_ssize_t size);
	void on_rx_rtp_h264(void *user_data, void *pkt, pj_ssize_t size);

    std::string ptime_to_register_date();
    bool is_equal(const char* p1, const pj_str_t& s2);
    std::string to_str(const pj_str_t& s);
    void start_dlg_device_search(pjsip_rx_data *rdata);
    std::string error_to_str(const pj_status_t& status);
	virtual int get_rtp_port();
	virtual std::string get_sdp_y(const pj_str_t& name, const std::string& desc_id_device);
	virtual bool to_key(std::string& key, pjsip_msg* pmsg);
	virtual info_dlg_ptr find_info(const pjsip_msg* pmsg);
	virtual bool find_other_from_sdp(std::string& v, const std::string& name, const pjmedia_sdp_session *sdp);
	virtual void stop_stream(info_dlg *pinfo);

    int decode_sdp(info_param_ptr &, const char **, const char **);

	static std::shared_ptr<server_sip> s_instance;

	static int s_module_id;

    pj_caching_pool m_cp;
    pj_thread_t *mp_thread = nullptr;
    pjsip_endpoint *mp_sip_endpt;
	pjmedia_endpt *mp_media_endpt = nullptr;
    pj_bool_t m_flag;
    struct pjsip_module m_module;
    pjsip_inv_callback m_inv_callback;
	std::string m_id;
	std::string m_ip;
	int m_port;
	pj_pool_t *mp_pool;
	std::map<std::string, info_dlg_ptr> m_dlgs;
	
};
typedef std::shared_ptr<server_sip> server_sip_ptr;

#endif // SERVER_SIP_H
