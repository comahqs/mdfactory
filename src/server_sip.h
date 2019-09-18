#ifndef SERVER_SIP_H
#define SERVER_SIP_H

#include "plugin.h"
#include <map>
#include <vector>
#include "module_sip.h"


class server_sip : public plugin, public std::enable_shared_from_this<server_sip>
{
public:
    virtual ~server_sip();
    virtual void on_read(frame_ptr& p_frame, std::size_t& count, point_type& point, socket_ptr& p_socket, context_ptr& p_context);
protected:
    virtual info_transaction_ptr get_transaction(info_param_ptr p_param);
    virtual int decode_sdp(info_param_ptr& p_param, const char** pp_start, const char** pp_end);

    std::map<std::string, info_transaction_ptr> m_transactions;
    module_sip_ptr mp_module = std::make_shared<module_sip_ptr::element_type>();
};
typedef std::shared_ptr<server_sip> server_sip_ptr;

#endif // SERVER_SIP_H
