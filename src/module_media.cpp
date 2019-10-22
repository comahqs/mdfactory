#include "module_media.h"
#include <boost/filesystem.hpp>
#include "utility_tool.h"
#include <pj/log.h>
#include <pjlib.h>
#include <iostream>

#define BUF_SIZE 4096*500
#define BUFFER_MAX 4096*500



bool module_media::start() {
	/*
	av_register_all();
	std::string file_output = "./1.mp4";
	if (boost::filesystem::exists(file_output))
	{
		boost::filesystem::remove(file_output);
	}
	int status = avformat_alloc_output_context2(&mp_output_format_cxt, nullptr, nullptr, file_output.c_str());
	if (0 > status)
	{
		return false;
	}
	auto fmt = mp_output_format_cxt->oformat;
	AVCodec *pcodec = nullptr;
	if (fmt->video_codec != AV_CODEC_ID_NONE) {
		pcodec = avcodec_find_encoder(fmt->video_codec);
		if (nullptr == pcodec)
		{
			return  false;
		}
		mp_output_stream = avformat_new_stream(mp_output_format_cxt, pcodec);
		if (nullptr == mp_output_stream)
		{
			return false;
		}
		mp_output_stream->id = mp_output_format_cxt->nb_streams - 1;
		auto c = mp_output_stream->codec;

		if (AVMEDIA_TYPE_VIDEO == pcodec->type)
		{
			c->codec_id = AV_CODEC_ID_H264;
			c->bit_rate = 400000;
			c->width = 1920;
			c->height = 1080;
			c->time_base = av_make_q(1, 25 );
			mp_output_stream->time_base = av_make_q(1, 25);
			c->gop_size = 1;
			c->pix_fmt = AV_PIX_FMT_YUV420P;
		}
		if (mp_output_format_cxt->oformat->flags & AVFMT_GLOBALHEADER)
		{
			c->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
		}
	}

	status = avcodec_open2(mp_output_stream->codec, pcodec, nullptr);
	if (0 > status)
	{
		return  false;
	}

	printf("==========输出文件信息==========\n");
	av_dump_format(mp_output_format_cxt, 0, file_output.c_str(), 1);
	printf("============================\n");

	if (!(fmt->flags & AVFMT_NOFILE))
	{
		status = avio_open(&mp_output_format_cxt->pb, file_output.c_str(), AVIO_FLAG_WRITE);
		if (status < 0)
		{
			return  false;
		}
	}

	status = avformat_write_header(mp_output_format_cxt, nullptr);
	if (status < 0)
	{
		return  false;
	}
	*/
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
	/*
	static std::ofstream stream;
	if (!stream.is_open())
	{
		stream.open("./ff.h264", std::ios::binary);
	}
	stream.write((const char*)pbuffer, len_buffer);
	return  0;
	*/
	/*
	if (nullptr == mp_output_format_cxt)
	{
		std::size_t len_sps = 0, len_pps = 0;
		const unsigned char* pbuffer_sps = nullptr, *pbuffer_pps = nullptr;
		for (std::size_t i = 0; i < len - 5; ++i)
		{
			if ((0x00 == *(pbuffer + i + 0) && 0x00 == *(pbuffer + i + 1) && 0x00 == *(pbuffer + i + 2) && 0x01 == *(pbuffer + i + 3))
				&& 0x07 == (*(pbuffer + i + 4) & 0x1F))
			{
				for (std::size_t j = i + 5; j < len - 5; ++j)
				{
					if (0x00 == *(pbuffer + j + 0) && 0x00 == *(pbuffer + j + 1) && 0x00 == *(pbuffer + j + 2) && 0x01 == *(pbuffer + j + 3))
					{
						pbuffer_sps = pbuffer + i;
						len_sps = j - i;
						break;
					}
				}
				continue;
			}
			if ((0x00 == *(pbuffer + i + 0) && 0x00 == *(pbuffer + i + 1) && 0x00 == *(pbuffer + i + 2) && 0x01 == *(pbuffer + i + 3))
				&& 0x08 == (*(pbuffer + i + 4) & 0x1F))
			{
				for (std::size_t j = i + 5; j < len - 5; ++j)
				{
					if (0x00 == *(pbuffer + j + 0) && 0x00 == *(pbuffer + j + 1) && 0x00 == *(pbuffer + j + 2) && 0x01 == *(pbuffer + j + 3))
					{
						pbuffer_pps = pbuffer + i;
						len_pps = j - i;
						break;
					}
				}
				if (nullptr == pbuffer_pps)
				{
					pbuffer_pps = pbuffer + i;
					len_pps = len - i;
				}
				continue;
			}
		}
		if (nullptr == pbuffer_sps || nullptr == pbuffer_pps)
		{
			return  -1;
		}

		av_register_all();


		if (avformat_open_input(&mp_input_format_cxt, "D:/ffmpeg-latest-win64-static/bin/2.mp4", nullptr, nullptr) < 0) {
			return  -1;
		}
		


		std::string file_output = "./1.mp4";
		if (boost::filesystem::exists(file_output))
		{
			boost::filesystem::remove(file_output);
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

			AVCodec *codec = avcodec_find_encoder(mp_output_format_cxt->oformat->video_codec);
			if (nullptr == codec)
			{
				return  -1;
			}
			auto p_output_video_code_ctx = avcodec_alloc_context3(codec);
			p_output_video_code_ctx->width = 1280;
			p_output_video_code_ctx->height = 720;
			//p_output_video_code_ctx->sample_aspect_ratio = p_input_video_code_ctx->sample_aspect_ratio;
			p_output_video_code_ctx->pix_fmt = AV_PIX_FMT_YUV420P;
#if 0
			{
				int extradata_len = 8 + len_sps - 4 + 1 + 2 + len_pps - 4;
				p_output_video_code_ctx->extradata = (uint8_t*)av_mallocz(extradata_len + AV_INPUT_BUFFER_PADDING_SIZE);
				p_output_video_code_ctx->extradata_size = extradata_len;
				p_output_video_code_ctx->extradata[0] = 0x01;
				p_output_video_code_ctx->extradata[1] = pbuffer_sps[4 + 1];
				p_output_video_code_ctx->extradata[2] = pbuffer_sps[4 + 2];
				p_output_video_code_ctx->extradata[3] = pbuffer_sps[4 + 3];
				p_output_video_code_ctx->extradata[4] = 0xFC | 3;
				p_output_video_code_ctx->extradata[5] = 0xE0 | 1;
				int tmp = len_sps - 4;
				p_output_video_code_ctx->extradata[6] = (tmp >> 8) & 0x00ff;
				p_output_video_code_ctx->extradata[7] = tmp & 0x00ff;
				int i = 0;
				for (i = 0; i < tmp; i++) {
					p_output_video_code_ctx->extradata[8 + i] = pbuffer_sps[4 + i];
				}
				p_output_video_code_ctx->extradata[8 + tmp] = 0x01;
				int tmp2 = len_pps - 4;
				p_output_video_code_ctx->extradata[8 + tmp + 1] = (tmp2 >> 8) & 0x00ff;
				p_output_video_code_ctx->extradata[8 + tmp + 2] = tmp2 & 0x00ff;
				for (i = 0; i < tmp2; i++) {
					p_output_video_code_ctx->extradata[8 + tmp + 3 + i] = pbuffer_pps[4 + i];
				}
				{
					std::stringstream stream;
					for (int i = 0; i < p_output_video_code_ctx->extradata_size; ++i)
					{
						stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(p_output_video_code_ctx->extradata[i])<<" ";
					}
					LOG_DEBUG_PJ("extradata: "<<stream.str());
				}
				memset(p_output_video_code_ctx->extradata + p_output_video_code_ctx->extradata_size, 0x00, AV_INPUT_BUFFER_PADDING_SIZE);
			}
#endif

#if 1
			p_output_video_code_ctx->extradata = (uint8_t*)av_malloc(len_sps + len_pps + AV_INPUT_BUFFER_PADDING_SIZE);
			memcpy(p_output_video_code_ctx->extradata, pbuffer, len_sps + len_pps);
			p_output_video_code_ctx->extradata_size = len_sps + len_pps;
			memset(p_output_video_code_ctx->extradata + p_output_video_code_ctx->extradata_size, 0x00, AV_INPUT_BUFFER_PADDING_SIZE);
#endif


			p_output_video_code_ctx->time_base = av_make_q(1, 25);
			p_output_video_code_ctx->framerate = av_make_q(1, 25);
			p_output_video_code_ctx->gop_size = 1;
			p_output_video_code_ctx->max_b_frames = 0;
			if (mp_output_format_cxt->oformat->flags & AVFMT_GLOBALHEADER)
			{
				//p_output_video_code_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
			}
			//p_output_video_code_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

			//p_output_video_code_ctx->bit_rate = p_input_video_code_ctx->bit_rate;


			p_output_video_code_ctx->profile = 0x4d;
			p_output_video_code_ctx->level = 0x1f;
			p_output_video_code_ctx->bits_per_raw_sample = 0x08;
			p_output_video_code_ctx->field_order = AV_FIELD_PROGRESSIVE;
			p_output_video_code_ctx->color_range = AVCOL_RANGE_JPEG;
			p_output_video_code_ctx->color_primaries = AVCOL_PRI_BT709;
			p_output_video_code_ctx->color_trc = AVCOL_TRC_BT709;
			p_output_video_code_ctx->colorspace = AVCOL_SPC_BT709;
			p_output_video_code_ctx->chroma_sample_location = AVCHROMA_LOC_LEFT;
			avcodec_parameters_from_context(p_output_video_stream->codecpar, p_output_video_code_ctx);
			p_output_video_stream->codecpar->format = 0x0C;
			p_output_video_stream->avg_frame_rate = av_make_q(25, 1);
			p_output_video_stream->r_frame_rate = av_make_q(25, 1);
			p_output_video_stream->time_base = av_make_q(1, 25);

			//avcodec_parameters_to_context(p_output_video_code_ctx, p_output_video_stream->codecpar);
			//auto ret = avcodec_open2(p_output_video_code_ctx, codec, nullptr);
			auto ret = avcodec_open2(p_output_video_code_ctx, codec, nullptr);
			if (0 > ret) {
				LOG_ERROR("打开输出解码器失败:" << ret);
				return -1;
			}
			
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
	
	

	AVPacket pkt;
	av_init_packet(&pkt);
	pkt.flags |= is_idr_frame(pbuffer, len) ? AV_PKT_FLAG_KEY : 0;
	
	//pkt.flags |= AV_PKT_FLAG_KEY;
	pkt.stream_index = 0;
	pkt.data = const_cast<unsigned char*>(pbuffer);
	pkt.size = len;

	pkt.pts = s_pts++ * 250;
	pkt.dts = pkt.pts;
	//av_packet_rescale_ts(&pkt, c->time_base, mp_output_stream->time_base);
	auto status = av_interleaved_write_frame(mp_output_format_cxt, &pkt);
	if (status < 0)
	{
		char tmp_msg[1024] = { 0 };
		av_strerror(status, tmp_msg, 1024);
		LOG_ERROR_PJ("处理视频数据时发生错误:" << tmp_msg << "; 错误代码:"<<status);
		return  -1;
	}
	*/



    if (nullptr == mp_buffer)
    {
		mp_buffer = (unsigned char*)av_mallocz(sizeof(unsigned char) * BUF_SIZE);
    }
	if (m_buffer_len + len > BUFFER_MAX)
	{
		return -2;
	}
	memmove(mp_buffer + m_buffer_len, pbuffer, len);
	m_buffer_len += len;
	m_condition.notify_one();

	static std::thread s([this]() {
		av_register_all();
		/*
		pj_thread_desc rtpdesc;
		pj_thread_t *thread = 0;
		if (!pj_thread_is_registered())
		{
			pj_thread_register(nullptr, rtpdesc, &thread);
		}
		*/
		if (nullptr == mp_input_format_cxt)
		{
			std::string file_output = "./1.flv";
			if (boost::filesystem::exists(file_output))
			{
				boost::system::error_code ec;
				boost::filesystem::remove(file_output, ec);
				if (ec)
				{
					LOG_ERROR_PJ("删除文件失败:" << ec.message() << "; 文件:"<<file_output);
				}
			}

			mp_buffer_avio = (unsigned char*)av_mallocz(sizeof(unsigned char) * 1400);

			auto pio_cxt = avio_alloc_context(mp_buffer_avio, 1400, 0, this, module_media::read, nullptr, nullptr);
			if (!pio_cxt) {
				return -1;
			}

			//if (av_probe_input_buffer(pio_cxt, &mp_input_format, "", nullptr, 0, 0) < 0) {
			//return -1;
			//}
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
				p_output_video_code_ctx->time_base = av_make_q(1, 25);
				p_output_video_code_ctx->framerate = av_make_q(25, 1);
				
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
				p_output_video_stream->time_base = av_make_q(1,1000);
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
			{
				static std::ofstream stream;
				if (!stream.is_open())
				{
					stream.open("./cc.h264", std::ios::binary);
				}
				stream.write((const char*)p_packet->data, p_packet->size);
				stream.flush();
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

	
	return 0;
}

int module_media::read(void *opaque, uint8_t *buf, int buf_size) {
	auto pmedia = reinterpret_cast<module_media*>(opaque);
	if (nullptr == pmedia)
	{
		return  -1;
	}
	{
		std::unique_lock<std::mutex> lock(pmedia->m_mutex_condition);
		while (0 >= pmedia->m_buffer_len)
		{
			pmedia->m_condition.wait(lock);
		}
	}
	if (pmedia->m_buffer_len >= buf_size)
	{
		memmove(buf, pmedia->mp_buffer, buf_size);
		memmove(pmedia->mp_buffer, pmedia->mp_buffer + buf_size, pmedia->m_buffer_len - buf_size);
		pmedia->m_buffer_len = pmedia->m_buffer_len - buf_size;
		return buf_size;
	}
	else {
		memmove(buf, pmedia->mp_buffer, pmedia->m_buffer_len);
		auto len_move = pmedia->m_buffer_len;
		pmedia->m_buffer_len = 0;
		return len_move;
	}
	return  -1;
}