#include <iostream>
#include "service_net.h"
#include <thread>
#include <chrono>
#include "service_context.h"
#include "virsual_client.h"
#include "server_media.h"


int main(int , char** ){
    //GetACP();
    server_media s(5060);
    s.start();
    /*
    service_context_ptr p_service_context = std::make_shared<service_context>();

    service_net service(5060);
    service.start();

    {
        virsual_client client("127.0.0.1", 5060, p_service_context->get_context());
        client.play();
    }
    */
    //system("pause");
    std::this_thread::sleep_for(std::chrono::hours(1));
    //service.stop();
    return 0;
}
