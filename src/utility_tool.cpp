#include "utility_tool.h"
#include <boost/locale.hpp>
#include <mutex>
#include <iomanip>

std::string ansi_to_utf8(const std::string& data){
    return boost::locale::conv::to_utf<char>(data, "GBK");
}

std::string utf8_to_ansi(const std::string& data){
    return boost::locale::conv::from_utf<char>(data, "GBK");
}

void write_log(const std::string& tag, const std::string& msg){
    static std::mutex s_mutex;

    std::lock_guard<std::mutex> lock(s_mutex);
    std::cout<<tag<<"\t"<<msg<<std::endl;
}

bool split_str(std::vector<std::string>& params, const std::string& data, const char s){
    params.clear();
    auto count = data.size();
    std::size_t pos_start = 0;
    for(std::size_t i = 0; i < count; ++i){
        if(s == data[i]){
            params.push_back(data.substr(pos_start, i - pos_start));
            pos_start = i + 1;
        }
    }
    if(pos_start >= count){
        params.push_back("");
    }else{
        params.push_back(data.substr(pos_start));
    }
    return true;
}

std::string frame_to_str(const std::shared_ptr<std::vector<unsigned char>>& p_frame){
    if(!p_frame){
        return "";
    }
    std::stringstream tmp_stream;
    for(auto& d : *p_frame){
        tmp_stream<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<int>(d)<<" ";
    }
    return tmp_stream.str();
}

std::string ptime_to_str(const boost::posix_time::ptime& time){
    if(time.is_not_a_date_time()){
        return "";
    }
    try
    {
        return boost::gregorian::to_iso_extended_string(time.date()) + " " + boost::posix_time::to_simple_string(time.time_of_day());
    }
    catch(const std::exception&)
    {
    }
    return "";
}

const char* get_file_name(const char* path) {
	const char* p_end = path + strlen(path);
	for (auto p = p_end; p >= path; --p)
	{
		if ('/' == *p || '\\' == *p)
		{
			return p + 1;
		}
	}
	return path;
}