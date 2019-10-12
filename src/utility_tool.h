#ifndef UTILITY_TOOL_H
#define UTILITY_TOOL_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <boost/date_time.hpp>

std::string ansi_to_utf8(const std::string& data);
std::string utf8_to_ansi(const std::string& data);
void write_log(const std::string& tag, const std::string& msg);
bool split_str(std::vector<std::string>& params, const std::string& data, const char s);
std::string frame_to_str(const std::shared_ptr<std::vector<unsigned char>>& p_frame);
std::string ptime_to_str(const boost::posix_time::ptime& time);

#define LOG_ERROR(MSG) {std::stringstream tmp_stream;tmp_stream<<MSG;write_log("error", utf8_to_ansi(tmp_stream.str()));}
#define LOG_INFO(MSG) {std::stringstream tmp_stream;tmp_stream<<MSG;write_log("info", utf8_to_ansi(tmp_stream.str()));}
#define LOG_DEBUG(MSG) {std::stringstream tmp_stream;tmp_stream<<MSG;write_log("debug", utf8_to_ansi(tmp_stream.str()));}
#define LOG_WARN(MSG) {std::stringstream tmp_stream;tmp_stream<<MSG;write_log("warn", utf8_to_ansi(tmp_stream.str()));}


const char* get_file_name(const char* path);

#define LOG_ERROR_PJ(MSG)                                        \
    {                                                            \
        std::stringstream tmp_stream;                            \
        tmp_stream << MSG;                                       \
        PJ_LOG(1, (get_file_name(__FILE__), tmp_stream.str().c_str())); \
    }
#define LOG_WARN_PJ(MSG)                                         \
    {                                                            \
        std::stringstream tmp_stream;                            \
        tmp_stream << MSG;                                       \
        PJ_LOG(2, (get_file_name(__FILE__), tmp_stream.str().c_str())); \
    }
#define LOG_INFO_PJ(MSG)                                         \
    {                                                            \
        std::stringstream tmp_stream;                            \
        tmp_stream << MSG;                                       \
        PJ_LOG(3, (get_file_name(__FILE__), tmp_stream.str().c_str())); \
    }
#define LOG_DEBUG_PJ(MSG)                                        \
    {                                                            \
        std::stringstream tmp_stream;                            \
        tmp_stream << MSG;                                       \
        PJ_LOG(4, (get_file_name(__FILE__), tmp_stream.str().c_str())); \
    }



#endif
