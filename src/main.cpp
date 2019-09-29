#include <iostream>
#include <thread>
#include <chrono>
#include "virsual_client.h"
#include "server_sip.h"


int main(int , char** ){
    //GetACP();
	system("chcp 65001");
	auto psip = server_sip::get_instance();
	psip->start(5060);

    std::this_thread::sleep_for(std::chrono::hours(1));
	psip->stop();
    return 0;
}
