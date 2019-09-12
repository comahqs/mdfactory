#include "server_media.h"
#include "utility_tool.h"
#include "error_code.h"

server_media::~server_media()
{

}


void server_media::on_read(frame_ptr& p_frame, std::size_t& count, point_type& point, socket_ptr& p_socket, context_ptr& p_context){

}

int server_media::do_work(info_net_ptr p_info){
    return MD_SUCCESS;
}
