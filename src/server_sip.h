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


class server_sip
{
public:
    virtual ~server_sip();
    virtual bool start(const int& port);
    virtual void stop();

	static std::shared_ptr<server_sip> get_instance();
protected:
    static pj_bool_t at_rx_request(pjsip_rx_data *rdata);
    static pj_bool_t at_rx_response(pjsip_rx_data *rdata);
    static pj_status_t at_tx_request(pjsip_tx_data *tdata);
    static pj_status_t at_tx_response(pjsip_tx_data *tdata);
	static void at_tsx_state(pjsip_transaction *tsx, pjsip_event *event);
	static int worker_thread(void *arg);

	server_sip();
	pj_bool_t on_rx_request(pjsip_rx_data *rdata);
	pj_bool_t on_rx_response(pjsip_rx_data *rdata);
	pj_status_t on_tx_request(pjsip_tx_data *tdata);
	pj_status_t on_tx_response(pjsip_tx_data *tdata);
	void on_tsx_state(pjsip_transaction *tsx, pjsip_event *event);

    std::string ptime_to_register_date();
    bool is_equal(const char* p1, const pj_str_t& s2);
    std::string to_str(const pj_str_t& s);
    void start_dlg_device_search(pjsip_rx_data *rdata);
    std::string error_to_str(const pj_status_t& status);

    int decode_sdp(info_param_ptr &, const char **, const char **);

	static std::shared_ptr<server_sip> s_instance;

    pj_caching_pool m_cp;
    pj_thread_t *mp_thread = nullptr;
    pjsip_endpoint *mp_sip_endpt;
    pj_bool_t m_flag;
    struct pjsip_module m_module;
    pjsip_inv_callback m_inv_callback;
};
typedef std::shared_ptr<server_sip> server_sip_ptr;

#endif // SERVER_SIP_H
