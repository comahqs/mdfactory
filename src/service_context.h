#ifndef SERVICE_CONTEXT_H
#define SERVICE_CONTEXT_H


#include "plugin.h"
#include <boost/thread.hpp>
#include <vector>

class service_context : public i_service_context, public plugin{
public:
    virtual context_ptr get_context();
    virtual context_ptr create_context();
    virtual bool start_before();
    virtual void stop_after();

protected:
    static void handle_thread(context_ptr p_context);

    std::vector<boost::thread> m_threads;
    std::vector<context_ptr> m_contexts;
};
typedef std::shared_ptr<service_context> service_context_ptr;




#endif // SERVICE_CONTEXT_H
