#ifndef SERVER_SIP_H
#define SERVER_SIP_H

#include "plugin.h"
#include <map>
#include <vector>
#include "module_sip.h"
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>


class server_sip : public plugin
{
public:
    server_sip(const int& port);
    virtual ~server_sip();
    virtual bool start();
    virtual void stop();
protected:
    static pj_bool_t on_rx_request(pjsip_rx_data *rdata);
    static pj_bool_t on_rx_response(pjsip_rx_data *rdata);
    static pj_bool_t on_tx_request(pjsip_tx_data *tdata);
    static pj_bool_t on_tx_response(pjsip_tx_data *tdata);
    static void on_tsx_state(pjsip_transaction *tsx, pjsip_event *event);
    static int worker_thread(void *arg);
    static std::string ptime_to_register_date();

    int decode_sdp(info_param_ptr &, const char **, const char **);

    static pj_caching_pool m_cp;
    pj_thread_t *mp_thread = nullptr;
    static pjsip_endpoint *mp_sip_endpt;
    pj_bool_t m_flag;
    std::pair<pjsip_endpoint*, pj_bool_t*> m_thread_params;
    int m_port = 0;
    struct pjsip_module m_module;
};
typedef std::shared_ptr<server_sip> server_sip_ptr;

#endif // SERVER_SIP_H
