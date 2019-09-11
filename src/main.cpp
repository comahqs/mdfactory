#include <iostream>
#include "service_net.h"
#include <thread>
#include <chrono>


int main(int argc, char** argv){
    GetACP();
    service_net service(5060);
    service.start();
    //system("pause");
    std::this_thread::sleep_for(std::chrono::hours(1));
    service.stop();
    return 0;
}