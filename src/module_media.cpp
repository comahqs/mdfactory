#include "module_media.h"
#include <boost/filesystem.hpp>
#include "utility_tool.h"
#include <pj/log.h>
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
	if (boost::posix_time::second_clock::local_time() > s_time + boost::posix_time::seconds(60))
	{
		if (nullptr != mp_output_format_cxt)
		{
			stop();
			LOG_INFO_PJ("关闭文件");
		}
		return 0;
	}
	if (nullptr == mp_output_format_cxt)
	{
		if (5 > len || !(0x00 ==*(pbuffer + 0) && 0x00 == *(pbuffer + 1) && 0x00 == *(pbuffer + 2) && 0x01 == *(pbuffer + 3) && 0x07 == (*(pbuffer + 4) & 0x1F)))
		{
			return -1;
		}
		std::size_t len_ex = 0;
		const unsigned char* pbuffer_ex = nullptr;
		for (std::size_t i = 0; i < len - 5; ++i)
		{
			if (0x00 == *(pbuffer + i + 0) && 0x00 == *(pbuffer + i + 1) && 0x00 == *(pbuffer + i + 2) && 0x01 == *(pbuffer + i + 3))
			{
				if (0x07 != (*(pbuffer + i + 4) & 0x1F) && 0x08 != (*(pbuffer + i + 4) & 0x1F))
				{
					len_ex = i;
					pbuffer_ex = pbuffer;
					//len -= len_ex;
					//pbuffer = pbuffer + len_ex;
					break;
				}
			}
		}

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
			c->bit_rate = 200000;
			c->width = 1280;
			c->height = 720;
			//c->extradata = (uint8_t*)av_malloc(len_ex);
			//memcpy(c->extradata, pbuffer_ex, len_ex);
			//c->extradata_size = len_ex;
			c->time_base = av_make_q(1, 25);
			c->gop_size = 1;
			c->pix_fmt = AV_PIX_FMT_YUV420P;
			c->framerate = av_make_q(1, 25);
			
			avcodec_parameters_from_context(mp_output_stream->codecpar, mp_output_stream->codec);

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

		printf("==========输出文件信息==========\n");
		av_dump_format(mp_output_format_cxt, 0, file_output.c_str(), 1);
		printf("============================\n");
	}

	/*
	if (5 <= len && ((0x00 == *(pbuffer + 0) && 0x00 == *(pbuffer + 1) && 0x00 == *(pbuffer + 2) && 0x01 == *(pbuffer + 3) && 0x07 == (*(pbuffer + 4) & 0x1F))
		 || (0x00 == *(pbuffer + 0) && 0x00 == *(pbuffer + 1) && 0x00 == *(pbuffer + 2) && 0x01 == *(pbuffer + 3) && 0x08 == (*(pbuffer + 4) & 0x1F))))
	{
		return 0;
	}
	*/

	AVPacket pkt;
	AVCodecContext *c = mp_output_stream->codec;
	av_init_packet(&pkt);
	pkt.flags |= is_idr_frame(pbuffer, len) ? AV_PKT_FLAG_KEY : 0;
	pkt.stream_index = mp_output_stream->index;
	pkt.data = const_cast<unsigned char*>(pbuffer);
	pkt.size = len;

	pkt.pts = s_pts++;
	pkt.dts = pkt.pts;
	av_packet_rescale_ts(&pkt, c->time_base, mp_output_stream->time_base);
	auto status = av_interleaved_write_frame(mp_output_format_cxt, &pkt);
	if (status < 0)
	{
		char tmp_msg[1024] = { 0 };
		av_strerror(status, tmp_msg, 1024);
		LOG_ERROR_PJ("处理视频数据时发生错误:" << tmp_msg << "; 错误代码:"<<status);
		return  -1;
	}


	/*
	if (m_buffer_len + len > BUFFER_MAX)
	{
		return -2;
	}
	if (0 != m_buffer_offset)
	{
		memmove(mp_buffer, mp_buffer + m_buffer_offset, m_buffer_len - m_buffer_offset);
		m_buffer_offset = 0;
	}
	memmove(mp_buffer + m_buffer_len, pbuffer, len);
	m_buffer_len += len;

	if (nullptr == mp_input_format)
	{
		mp_buffer_avio = (unsigned char*)av_mallocz(sizeof(unsigned char) * BUF_SIZE);
		mp_buffer = (unsigned char*)av_mallocz(sizeof(unsigned char) * BUFFER_MAX);
		mp_ctx = avio_alloc_context(mp_buffer_avio, BUF_SIZE, 0, this, module_media::read_buffer, nullptr, nullptr);
		if (!mp_ctx) {
			return -1;
		}
		if (av_probe_input_buffer(mp_ctx, &mp_input_format, "", nullptr, 0, 0) < 0) {
			return -1;
		}
		mp_input_format_cxt = avformat_alloc_context();
		mp_input_format_cxt->pb = mp_ctx;
		if (avformat_open_input(&mp_input_format_cxt, "", mp_input_format, nullptr) < 0) {
			return  -1;
		}
		if (avformat_find_stream_info(mp_input_format_cxt, nullptr) < 0) {
			return -1;
		}

		int videoindex = -1;
		int audioindex = -1;
		for (int i = 0; i < mp_input_format_cxt->nb_streams; i++) {
			if ((mp_input_format_cxt->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO) &&
				(videoindex < 0)) {
				videoindex = i;
			}
			if ((mp_input_format_cxt->streams[i]->codec->codec_type == AVMEDIA_TYPE_AUDIO) &&
				(audioindex < 0)) {
				audioindex = i;
			}
		}

		if (videoindex < 0 || audioindex < 0) {
			return -1;
		}

		AVStream *pVst, *pAst;
		pVst = mp_input_format_cxt->streams[videoindex];
		pAst = mp_input_format_cxt->streams[audioindex];

		auto pVideoCodecCtx = pVst->codec;
		auto pAudioCodecCtx = pAst->codec;

		auto pVideoCodec = avcodec_find_decoder(pVideoCodecCtx->codec_id);
		if (!pVideoCodec) {
			return -1;
		}
		if (avcodec_open2(pVideoCodecCtx, pVideoCodec, nullptr) < 0) {
			return -1;
		}

		auto pAudioCodec = avcodec_find_decoder(pAudioCodecCtx->codec_id);
		if (!pAudioCodec) {
			return -1;
		}
		if (avcodec_open2(pAudioCodecCtx, pAudioCodec, nullptr) < 0) {
			return -1;
		}
	}

	

	

	int got_picture;
	uint8_t samples[AVCODEC_MAX_AUDIO_FRAME_SIZE * 3 / 2];
	AVFrame *pframe = avcodec_alloc_frame();
	AVPacket pkt;
	av_init_packet(&pkt);

	while (1) {
		if (av_read_frame(mp_input_format_cxt, &pkt) >= 0) {

			if (pkt.stream_index == videoindex) {
				fprintf(stdout, "pkt.size=%d,pkt.pts=%lld, pkt.data=0x%x.", pkt.size, pkt.pts, (unsigned int)pkt.data);
				avcodec_decode_video2(pVideoCodecCtx, pframe, &got_picture, &pkt);
				if (got_picture) {
					fprintf(stdout, "decode one video frame!\n");
				}
			}
			else if (pkt.stream_index == audioindex) {
				int frame_size = AVCODEC_MAX_AUDIO_FRAME_SIZE * 3 / 2;
				if (avcodec_decode_audio3(pAudioCodecCtx, (int16_t *)samples, &frame_size, &pkt) >= 0) {
					fprintf(stdout, "decode one audio frame!\n");
				}
			}
			av_free_packet(&pkt);
		}
	}

	av_free(buf);
	av_free(pframe);
	free_queue(&recvqueue);
	*/
	return 0;
}