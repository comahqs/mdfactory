#ifndef MODULE_MEDIA_H
#define MODULE_MEDIA_H

#include "plugin.h"
#include <condition_variable>
#include <thread>
#include <boost/coroutine2/all.hpp>
extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
}

class info_exchange {
public:
	const unsigned char* pbuffer;
	std::size_t len;
	boost::coroutines2::coroutine<void>::pull_type* psink;
};
typedef std::shared_ptr<info_exchange> info_exchange_ptr;

class module_media {
public:
	virtual bool start();
	virtual void stop();
	virtual int write(const unsigned char* pbuffer, const std::size_t& len);

protected:
	bool is_idr_frame(const unsigned char* pbuffer, const std::size_t& len);
	static int read(void *opaque, uint8_t *buf, int buf_size);

	unsigned char* mp_buffer_avio = nullptr;
	AVIOContext * mp_ctx = nullptr;

	unsigned char* mp_buffer = nullptr;
	std::size_t m_buffer_len = 0;
	AVFormatContext *mp_input_format_cxt = nullptr;
	AVFormatContext *mp_output_format_cxt = nullptr;

	std::condition_variable_any m_condition;
	std::mutex m_mutex_condition;
	std::shared_ptr<boost::coroutines2::coroutine<void>::push_type> mp_coroutine;
	info_exchange_ptr mp_exchange;
};
typedef std::shared_ptr<module_media> module_media_ptr;







#endif
