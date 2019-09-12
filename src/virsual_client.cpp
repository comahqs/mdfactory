#include "virsual_client.h"
#include "utility_tool.h"
#include <boost/bind.hpp>

#define LINE_END "\r\n"

virsual_client::virsual_client(const std::string& ip, const unsigned int& port, context_ptr p_context):m_ip(ip),m_port(port), mp_context(p_context)
{

}

void virsual_client::play(){

    boost::asio::spawn(*mp_context, boost::bind(&virsual_client::handle_play, this, _1));
}

void virsual_client::handle_play(boost::asio::yield_context yield){
    try{
        auto p_socket = std::make_shared<socket_ptr::element_type>(*mp_context);
        boost::system::error_code ec;

        point_type point(boost::asio::ip::address::from_string(m_ip), static_cast<unsigned short>(m_port));
         /*
        p_socket->async_connect(point, yield[ec]);
        if(ec){
            LOG_ERROR("连接远端时发生错误:"<<ec.message());
            return;
        }
        */

        {
            std::stringstream tmp_stream;
            tmp_stream<<"INVITE sip:00000000001310018021@192.168.40.66:7100 SIP/2.0"<<LINE_END
                <<"Via: SIP/2.0/UDP 192.168.40.55:7100;rport;branch=z9hG4bK2480933505"<<LINE_END
                <<"From: <sip:120105110228023020@192.168.40.55:7100>;tag=2249831759"<<LINE_END
                <<"To: <sip:00000000001310018021@192.168.40.66:7100>"<<LINE_END
                <<"Call-ID: 821763613"<<LINE_END
                <<"CSeq: 20 INVITE"<<LINE_END
                <<"Contact: <sip:120105110228023020@192.168.40.55:7100>"<<LINE_END
                <<"Content-Type: Application/SDP"<<LINE_END
                <<"Max-Forwards: 70"<<LINE_END
                <<"User-Agent: NCG V2.6.0.299938"<<LINE_END
                <<"Subject: 00000000001310018021:0,120105110228023020:0"<<LINE_END
                <<"Content-Length:   239"<<LINE_END
                <<LINE_END<<LINE_END
                <<"v=0"<<LINE_END
                <<"o=00000000001310018021 0 0 IN IP4 192.168.40.55"<<LINE_END
                <<"s=Play"<<LINE_END
                <<"c=IN IP4 192.168.40.55"<<LINE_END
                <<"t=0 0"<<LINE_END
                <<"m=video 5552 RTP/AVP 96 97 98"<<LINE_END
                <<"a=rtpmap:96 PS/90000"<<LINE_END
                <<"a=rtpmap:97 MPEG4/90000"<<LINE_END
                <<"a=rtpmap:98 H264/90000"<<LINE_END
                <<"a=recvonly"<<LINE_END
                <<"a=streamMode:MAIN"<<LINE_END
                <<"y=0999999999"<<LINE_END;
            p_socket->async_send_to(boost::asio::buffer(tmp_stream.str()), point, yield[ec]);
            if(ec){
                LOG_ERROR("发送数据时发生错误:"<<ec.message());
                return;
            }
        }
    }catch(const std::exception& e){
        LOG_INFO("点播时发生错误:"<<e.what());
    }
}
