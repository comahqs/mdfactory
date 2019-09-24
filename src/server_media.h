#ifndef SERVER_MEDIA_H
#define SERVER_MEDIA_H

#include "server_sip.h"


class server_media
{
public:
    server_media(const int port);
    virtual ~server_media();
    virtual bool start();
    virtual void stop();
protected:
    int m_port;
};

#endif // SERVER_MEDIA_H
