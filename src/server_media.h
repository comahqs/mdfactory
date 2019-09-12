#ifndef SERVER_MEDIA_H
#define SERVER_MEDIA_H

#include "server_sip.h"

class server_media : public server_sip
{
public:
    virtual ~server_media();
    virtual void on_read(frame_ptr& p_frame, std::size_t& count, point_type& point, socket_ptr& p_socket, context_ptr& p_context);

protected:
    virtual int do_work(info_net_ptr p_proxy);
};

#endif // SERVER_MEDIA_H
