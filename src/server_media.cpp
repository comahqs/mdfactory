#include "server_media.h"
#include "utility_tool.h"
#include "error_code.h"

static pjsip_endpoint *sip_endpt;
static pj_bool_t       quit_flag;
static pjsip_dialog   *dlg;

#define SAME_BRANCH	0
#define ACK_HAS_SDP	1

static void on_tsx_state(pjsip_transaction *tsx, pjsip_event *event);

pj_bool_t on_rx_request(pjsip_rx_data *rdata){
    PJ_LOG(3,("", "on_rx_request"));
    return PJ_TRUE;
}

pj_bool_t on_rx_response(pjsip_rx_data *rdata){
    PJ_LOG(3,("", "on_rx_response"));
    return PJ_FALSE;
}

pj_bool_t on_tx_request(pjsip_tx_data *tdata){
    PJ_LOG(3,("", "on_tx_request"));
    return PJ_TRUE;
}

pj_bool_t on_tx_response(pjsip_tx_data *tdata){
    PJ_LOG(3,("", "on_tx_response"));
    return PJ_TRUE;
}

static pjsip_module mod_app =
{
    NULL, NULL,			    /* prev, next.		*/
    { "mod-app", 7 },		    /* Name.			*/
    -1,				    /* Id			*/
    PJSIP_MOD_PRIORITY_APPLICATION, /* Priority			*/
    NULL,			    /* load()			*/
    NULL,			    /* start()			*/
    NULL,			    /* stop()			*/
    NULL,			    /* unload()			*/
    &on_rx_request,			    /* on_rx_request()		*/
    &on_rx_response,			    /* on_rx_response()		*/
    &on_tx_request,			    /* on_tx_request.		*/
    &on_tx_response,			    /* on_tx_response()		*/
    &on_tsx_state		    /* on_tsx_state()		*/
};


/* Worker thread */
static int worker_thread(void *arg)
{
    PJ_UNUSED_ARG(arg);
    while (!quit_flag) {
    pj_time_val timeout = {0, 500};
    try{
pjsip_endpt_handle_events(sip_endpt, &timeout);
    }catch(const std::exception& e){
PJ_LOG(3,("", e.what()));
    }
    
    }

    return 0;
}

/* Send request */
static void send_request(const pjsip_method *method,
             int cseq,
             const pj_str_t *branch,
             pj_bool_t with_offer)
{
    pjsip_tx_data *tdata;
    pj_str_t dummy_sdp_str =
    {
    "v=0\r\n"
    "o=- 3360842071 3360842071 IN IP4 192.168.0.68\r\n"
    "s=pjmedia\r\n"
    "c=IN IP4 192.168.0.68\r\n"
    "t=0 0\r\n"
    "m=audio 4000 RTP/AVP 0 101\r\n"
    "a=rtcp:4001 IN IP4 192.168.0.68\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=sendrecv\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-15\r\n",
    0
    };
    pj_status_t status;

    status = pjsip_dlg_create_request(dlg, method, cseq, &tdata);
    pj_assert(status == PJ_SUCCESS);

    if (branch) {
    pjsip_via_hdr *via;

    via = (pjsip_via_hdr*) pjsip_msg_find_hdr(tdata->msg, PJSIP_H_VIA, NULL);
    pj_strdup(tdata->pool, &via->branch_param, branch);
    }

    if (with_offer) {
    pjsip_msg_body *body;
    pj_str_t mime_application = { "application", 11};
    pj_str_t mime_sdp = {"sdp", 3};


    dummy_sdp_str.slen = pj_ansi_strlen(dummy_sdp_str.ptr);
    body = pjsip_msg_body_create(tdata->pool,
                     &mime_application, &mime_sdp,
                     &dummy_sdp_str);
    tdata->msg->body = body;
    }

    status = pjsip_dlg_send_request(dlg, tdata, -1, NULL);
    pj_assert(status == PJ_SUCCESS);
}

static void on_tsx_state(pjsip_transaction *tsx, pjsip_event *event)
{
    PJ_LOG(3,("", "on_tsx_state"));
    if (tsx->role == PJSIP_ROLE_UAC) {
    if (tsx->method.id == PJSIP_INVITE_METHOD && tsx->state == PJSIP_TSX_STATE_TERMINATED) {
#if SAME_BRANCH
        send_request(&pjsip_ack_method, tsx->cseq, &tsx->branch, ACK_HAS_SDP);
#else
        send_request(&pjsip_ack_method, tsx->cseq, NULL, ACK_HAS_SDP);
#endif
    }

    } else {
    if (event->type == PJSIP_EVENT_RX_MSG && tsx->state == PJSIP_TSX_STATE_TRYING) {
        pjsip_tx_data *tdata;

        pjsip_dlg_create_response(dlg, event->body.tsx_state.src.rdata,
                      200, NULL, &tdata);
        pjsip_dlg_send_response(dlg, tsx, tdata);
    }
    }
}

server_media::server_media(const int port):m_port(port){
}


server_media::~server_media()
{

}


bool server_media::start(){
    pj_caching_pool cp;
        pj_thread_t *thread;
        pj_pool_t *pool;
        pj_status_t status;


        /* Must init PJLIB first: */
        status = pj_init();
        PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);


        /* Then init PJLIB-UTIL: */
        status = pjlib_util_init();
        PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

        /* Must create a pool factory before we can allocate any memory. */
        pj_caching_pool_init(&cp, &pj_pool_factory_default_policy, 0);


        /* Create the endpoint: */
        status = pjsip_endpt_create(&cp.factory, "sipstateless",
                    &sip_endpt);
        PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

        /*
         * Add UDP transport, with hard-coded port
         */
        {
        pj_sockaddr_in addr;

        addr.sin_family = pj_AF_INET();
        addr.sin_addr.s_addr = 0;
        addr.sin_port = pj_htons(m_port);

        status = pjsip_udp_transport_start( sip_endpt, &addr, NULL, 1, NULL);
        if (status != PJ_SUCCESS) {
            PJ_LOG(3,("",
                  "Error starting UDP transport (port in use?)"));
            return false;
        }
        }

        status = pjsip_tsx_layer_init_module(sip_endpt);
        pj_assert(status == PJ_SUCCESS);

        status = pjsip_ua_init_module(sip_endpt, NULL);
        pj_assert(status == PJ_SUCCESS);

        /*
         * Register our module to receive incoming requests.
         */
        status = pjsip_endpt_register_module( sip_endpt, &mod_app);
        PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

        pool = pjsip_endpt_create_pool(sip_endpt, "", 1000, 1000);

        status = pj_thread_create(pool, "", &worker_thread, NULL, 0, 0, &thread);
        PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    std::this_thread::sleep_for(std::chrono::hours(1));
}

void server_media::stop(){

}
