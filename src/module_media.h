#ifndef MODULE_MEDIA_H
#define MODULE_MEDIA_H

#include "plugin.h"
#include <condition_variable>
#include <thread>
extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
}

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
};
typedef std::shared_ptr<module_media> module_media_ptr;







#endif
