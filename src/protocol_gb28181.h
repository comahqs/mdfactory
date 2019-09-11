#ifndef PROTOCOL_GB28181_H__
#define PROTOCOL_GB28181_H__


#include "plugin.h"

#define ALGORITHM_MD5 "MD5"

#define ACTION_REGISTER "REGISTER"
#define ACTION_OK "OK"
#define ACTION_UNAUTHORIZED "Unauthorized"
#define PARAM_TAG "tag"
#define PARAM_VIA "Via"
#define PARAM_VIA_VERSION "Via@version"
#define PARAM_VIA_ADDRESS "Via@address"
#define PARAM_FROM "From"
#define PARAM_FROM_SIP "From@sip"
#define PARAM_FROM_TAG "From@tag"
#define PARAM_TO "To"
#define PARAM_TO_SIP "To@sip"
#define PARAM_TO_TAG "To@tag"
#define PARAM_VIA_ADDRESS "Via@address"
#define PARAM_WWW_AUTHENTICATE "WWW-Authenticate"
#define PARAM_CSEQ "CSeq"
#define PARAM_CSEQ_INDEX "CSeq@index"
#define PARAM_CSEQ_ACTION "CSeq@action"
#define PARAM_AUTHENTICATE "Authorization"
#define PARAM_AUTHENTICATE_USERNAME "Authorization@username"
#define PARAM_AUTHENTICATE_REALM "Authorization@realm"
#define PARAM_AUTHENTICATE_NONCE "Authorization@nonce"
#define PARAM_AUTHENTICATE_URI "Authorization@uri"
#define PARAM_AUTHENTICATE_RESPONSE "Authorization@response"
#define PARAM_AUTHENTICATE_ALGORITHM "Authorization@algorithm"
#define PARAM_DATE "Date"
#define PARAM_CALL_ID "Call-ID"
#define PARAM_CONTACT "Contact"
#define PARAM_MAX_FORWARDS "Max-Forwards"
#define PARAM_EXPIRES "Expires"
#define PARAM_CONTENT_LENGTH "Content-Length"

class protocol_gb28181{
public:
    virtual int decode(info_param_ptr& p_param, frame_ptr& p_frame);
    virtual int encode(frame_ptr& p_frame, info_param_ptr& p_param);

    virtual std::string random_str();
protected:
    virtual bool find_line(const char** pp_line_start, const char** pp_line_end, const char** pp_start, const char* p_end);
    virtual bool find_param(const char** pp_param_start, const char** pp_param_end, const char** pp_start, const char* p_end, const char s);
    virtual bool remove_char(const char** pp_start, const char** pp_end, const char s);
    virtual bool remove_rn(const char** pp_start, const char** pp_end);
    virtual bool decode_kv(std::map<std::string, std::string>& kv, const std::string& tag, const char **pp_line_start, const char *p_line_end, const char s);

};
typedef std::shared_ptr<protocol_gb28181> protocol_gb28181_ptr;








#endif // PROTOCOL_GB28181_H__