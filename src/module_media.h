#ifndef MODULE_MEDIA_H
#define MODULE_MEDIA_H

#include "plugin.h"
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

	/*
	unsigned char* mp_buffer_avio = nullptr;
	AVIOContext * mp_ctx = nullptr;

	unsigned char* mp_buffer = nullptr;
	std::size_t m_buffer_offset = 0;
	std::size_t m_buffer_len = 0;
	AVInputFormat *mp_input_format = nullptr;
	AVFormatContext *mp_input_format_cxt = nullptr;
	*/

	AVFormatContext *mp_output_format_cxt = nullptr;
	AVStream *mp_output_stream = nullptr;
};
typedef std::shared_ptr<module_media> module_media_ptr;







#endif
