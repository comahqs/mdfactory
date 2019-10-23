#include "module_media.h"
#include <boost/filesystem.hpp>
#include "utility_tool.h"
#include <pj/log.h>
#include <pjlib.h>
#include <iostream>


#define BUF_SIZE 4096*500
#define BUFFER_MAX 4096*500



bool module_media::start() {
	return true;
}

void module_media::stop() {
	if (nullptr != mp_output_format_cxt)
	{
		av_write_trailer(mp_output_format_cxt);
	}
	if (mp_output_format_cxt && !(mp_output_format_cxt->oformat->flags & AVFMT_NOFILE)) {
		avio_close(mp_output_format_cxt->pb);
	}
	if (nullptr != mp_output_format_cxt)
	{
		avformat_free_context(mp_output_format_cxt);
		mp_output_format_cxt = nullptr;
	}
}

bool module_media::is_idr_frame(const unsigned char* pbuffer, const std::size_t& len) {
	for (std::size_t i = 3; i < len; ++i)
	{
		if (0x00 == *(pbuffer + i - 3) && 0x00 == *(pbuffer + i - 2) && 0x01 == *(pbuffer + i - 1))
		{
			unsigned char code = (*(pbuffer + i) & 0x1F);
			if (0x07 == code || 0x08 == code || 0x05 == code)
			{
				return true;
			}
		}
	}
	return false;
}

int module_media::write(const unsigned char* pbuffer, const std::size_t& len_buffer) {
	static int s_pts = 0;
	static boost::posix_time::ptime s_time = boost::posix_time::second_clock::local_time();

	std::size_t len = len_buffer;
	if (boost::posix_time::second_clock::local_time() > s_time + boost::posix_time::seconds(2000))
	{
		if (nullptr != mp_output_format_cxt)
		{
			stop();
			LOG_INFO_PJ("关闭文件");
		}
		return 0;
	}
	if (!mp_coroutine)
	{
		mp_exchange = std::make_shared<info_exchange>();
		mp_coroutine = std::make_shared<boost::coroutines2::coroutine<void>::push_type>([this](boost::coroutines2::coroutine<void>::pull_type & sink) {
			if (nullptr == mp_input_format_cxt)
			{
				std::string file_output = "./1.flv";
				if (boost::filesystem::exists(file_output))
				{
					boost::system::error_code ec;
					boost::filesystem::remove(file_output, ec);
					if (ec)
					{
						LOG_ERROR_PJ("删除文件失败:" << ec.message() << "; 文件:" << file_output);
					}
				}

				mp_buffer_avio = (unsigned char*)av_mallocz(sizeof(unsigned char) * 1400);
				mp_exchange->psink = &sink;
				auto pio_cxt = avio_alloc_context(mp_buffer_avio, 1400, 0, mp_exchange.get(), module_media::read, nullptr, nullptr);
				if (!pio_cxt) {
					return -1;
				}

				mp_input_format_cxt = avformat_alloc_context();
				mp_input_format_cxt->pb = pio_cxt;
				mp_input_format_cxt->flags = AVFMT_FLAG_CUSTOM_IO;
				if (avformat_open_input(&mp_input_format_cxt, "", nullptr, nullptr) < 0) {
					return  -1;
				}
				if (avformat_find_stream_info(mp_input_format_cxt, nullptr) < 0) {
					return -1;
				}

				AVCodecContext *p_input_video_code_ctx = nullptr;
				{
					AVCodec *pi_code = nullptr;
					auto index_stream = av_find_best_stream(mp_input_format_cxt, AVMEDIA_TYPE_VIDEO, -1, -1, &(pi_code), 0);
					if (0 > index_stream)
					{
						LOG_ERROR("获取视频索引失败:" << index_stream);
						return -1;
					}
					auto p_input_video_stream = mp_input_format_cxt->streams[index_stream];
					p_input_video_code_ctx = avcodec_alloc_context3(pi_code);
					avcodec_parameters_to_context(p_input_video_code_ctx, p_input_video_stream->codecpar);
					p_input_video_code_ctx->framerate = av_guess_frame_rate(mp_input_format_cxt, p_input_video_stream, nullptr);
					auto ret = avcodec_open2(p_input_video_code_ctx, pi_code, nullptr);
					if (ret < 0)
					{
						return -1;
					}
				}


				if (0 > avformat_alloc_output_context2(&mp_output_format_cxt, nullptr, nullptr, file_output.c_str()))
				{
					LOG_ERROR("打开输出流失败");
					return -1;
				}

				if (!(mp_output_format_cxt->oformat->flags & AVFMT_NOFILE))
				{
					auto ret = avio_open(&(mp_output_format_cxt->pb), file_output.c_str(), AVIO_FLAG_WRITE);
					if (ret < 0)
					{
						return -1;
					}
				}

				{
					auto p_output_video_stream = avformat_new_stream(mp_output_format_cxt, nullptr);
					if (nullptr == p_output_video_stream)
					{
						LOG_ERROR("新建输出流失败");
						return -1;
					}

					AVCodec *codec = avcodec_find_encoder(p_input_video_code_ctx->codec_id);
					if (nullptr == codec)
					{
						return  -1;
					}
					auto p_output_video_code_ctx = avcodec_alloc_context3(codec);
					p_output_video_code_ctx->width = p_input_video_code_ctx->width;
					p_output_video_code_ctx->height = p_input_video_code_ctx->height;
					p_output_video_code_ctx->sample_aspect_ratio = p_input_video_code_ctx->sample_aspect_ratio;
					if (nullptr != codec->pix_fmts)
					{
						p_output_video_code_ctx->pix_fmt = codec->pix_fmts[0];
					}
					else
					{
						p_output_video_code_ctx->pix_fmt = p_input_video_code_ctx->pix_fmt;
					}
					//p_output_video_code_ctx->time_base = av_make_q(1, 25);
					//p_output_video_code_ctx->framerate = av_make_q(25, 1);

					//p_output_video_code_ctx->bit_rate = p_input_video_code_ctx->bit_rate;

					//auto ret = avcodec_open2(p_output_video_code_ctx, codec, nullptr);
					auto ret = avcodec_open2(p_input_video_code_ctx, codec, nullptr);
					if (0 > ret) {
						LOG_ERROR("打开输出解码器失败:" << ret);
						return -1;
					}
					avcodec_parameters_from_context(p_output_video_stream->codecpar, p_output_video_code_ctx);
					//p_output_video_stream->avg_frame_rate = av_make_q(25, 1);
					//p_output_video_stream->r_frame_rate = av_make_q(25, 1);
					//p_output_video_stream->time_base = av_make_q(1, 1000);
					//p_output_video_stream->avg_frame_rate = p_output_video_stream->avg_frame_rate;
					//p_output_video_stream->r_frame_rate = p_output_video_stream->r_frame_rate;
					//p_output_video_code_ctx->gop_size = 30;
					//p_output_video_code_ctx->max_b_frames = 0;
				}

				auto ret = avformat_write_header(mp_output_format_cxt, nullptr);
				if (ret < 0)
				{
					return  -1;
				}

				printf("==========输出文件信息==========\n");
				av_dump_format(mp_output_format_cxt, 0, file_output.c_str(), 1);
				printf("============================\n");
			}


			auto p_packet = av_packet_alloc();
			while (true)
			{
				auto ret = av_read_frame(mp_input_format_cxt, p_packet);
				if (0 != ret)
				{
					return 0;
				}
				static int sindex = 0;
				p_packet->pts = sindex * 40;
				p_packet->dts = p_packet->pts;
				sindex++;
				//av_packet_rescale_ts(p_packet, mp_output_format_cxt->streams[0]->time_base, mp_output_format_cxt->streams[0]->codec->time_base);

				auto type = mp_input_format_cxt->streams[p_packet->stream_index]->codecpar->codec_type;
				if (AVMEDIA_TYPE_VIDEO == type)
				{
					auto status = av_interleaved_write_frame(mp_output_format_cxt, p_packet);
					if (status < 0)
					{
						char tmp_msg[1024] = { 0 };
						av_strerror(status, tmp_msg, 1024);
						LOG_ERROR_PJ("处理视频数据时发生错误:" << tmp_msg << "; 错误代码:" << status);
						return  -1;
					}
				}
				av_packet_unref(p_packet);
			}
			av_packet_free(&p_packet);
		});
	}
	

	mp_exchange->pbuffer = pbuffer;
	mp_exchange->len = len_buffer;
	(*mp_coroutine)();
	
	return 0;
}

int module_media::read(void *opaque, uint8_t *buf, int buf_size) {
	auto pinfo = reinterpret_cast<info_exchange*>(opaque);
	if (nullptr == pinfo)
	{
		return  -1;
	}
	while (0 >= pinfo->len)
	{
		(*(pinfo->psink))();
	}
	memmove(buf, pinfo->pbuffer, pinfo->len);
	auto len = pinfo->len;
	pinfo->pbuffer = nullptr;
	pinfo->len = 0;
	return len;
	return  -1;
}