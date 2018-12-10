//参考调用openssl对外导出的方法

#include <lua.h>
#include <lauxlib.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static int l_encrypt_pem(lua_State *L);
static int l_decrypt_pem(lua_State *L);
static int l_process_check(lua_State *L);
static int l_process_signature(lua_State *L);
static int l_pri_encrypt_pem(lua_State *L);
static int l_pub_decrypt_pem(lua_State *L);

// static int encrypt(const char* in, int in_len, char* out,int out_len, const char* szModule, const char* szPublic);
// static int decrypt(const char* in, int in_len, char* out,int out_len, const char* szModule, const char* szPrivate, const char* szPublic);
// static char str_Public[] = "10001";

static const struct luaL_reg luarsa[] = {
    {"encrypt_pem", l_encrypt_pem},
    {"decrypt_pem", l_decrypt_pem},
    {"process_check", l_process_check},
    {"process_signature", l_process_signature},
    {"pri_encrypt_pem", l_pri_encrypt_pem},
    {"pub_decrypt_pem", l_pub_decrypt_pem},	
    {NULL, NULL}
};

int luaopen_luarsa(lua_State * L)
{
    luaL_openlib(L, "luarsa", luarsa, 0);
    return 1;
}

static char *cpystrn(char *dst, char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }

    while (--n) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }

        dst++;
        src++;
    }

    *dst = '\0';

    return dst;
}

static void get_ssl_error(lua_State * L, char * extra)
{
    char *p, *last;
    int n;
    char errstr[1024];
    p = errstr;
    last = errstr + 1024 - 2;
    p = cpystrn(p, extra, last - p);
    p = cpystrn(p, "(", last - p);

	for(;;){
		n = ERR_get_error();

		if (n == 0) {
			break;
		}else{
			if (p >= last) {
				break;
			}
			*p++ = ' ';
			ERR_error_string_n(n, p, last - p);
			while (p < last && *p) {
				p++;
			}
		}
	}
	p = cpystrn(p, ")", last - p);
    *p = '\0';
    lua_pushstring(L, errstr);
}

//base64解码
static int Base64Decode(const char *src, int src_len, char *dst, int dst_len)
{
    BIO *b = BIO_new(BIO_f_base64());
    BIO_set_flags(b, BIO_FLAGS_BASE64_NO_NL);
    b = BIO_push(b, BIO_new_mem_buf((void *)src, src_len));

    int ret = BIO_read(b, dst, dst_len);
    if (ret > 0)
        dst[ret] = '\0';

    BIO_free_all(b);

    return ret;
}

//base64编码
static int Base64Encode(const char *src, int src_len, char *dst, int dst_len)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *b = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, b);
    BIO_write(b64, src, src_len);
    BIO_flush(b64);
    int ret = BIO_read(b, dst, dst_len);
    if (ret > 0){
        dst[ret] = '\0';
    }
    BIO_free_all(b64);
    return ret;
}

//取公钥
static RSA *ReadRSAPublicKey(const char *pvKey, int pvKeyLen)
{
    RSA *rsa = NULL;
    BIO *b = NULL;
    b = BIO_new_mem_buf((void *)pvKey, pvKeyLen);
    if (b != NULL)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(b, NULL, NULL, NULL);
    }

    BIO_free_all(b);

    return rsa;
}

//取私钥
static RSA *ReadRSAPrivateKey(const char *pvKey, int pvKeyLen)
{
    RSA *rsa = NULL;
    BIO *b = NULL;
    b = BIO_new_mem_buf((void *)pvKey, pvKeyLen);
    if (b != NULL)
    {
        rsa = PEM_read_bio_RSAPrivateKey(b, NULL, NULL, NULL);
    }

    BIO_free_all(b);

    return rsa;
}

//the public key must be format like "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCubeE0twrq2FTKq67mwVSFZ2d8\n...\n-----END PUBLIC KEY-----\n"
//公钥加密
static int l_encrypt_pem(lua_State * L)
{
    size_t str_in_len = 0;

    const char *str_in = lua_tolstring(L, 1, &str_in_len);
    if(str_in == NULL)
    {
        lua_pushnumber (L, -1);
        lua_pushstring (L, "argument #1 should be string or number");
        return 2;
    }
    size_t stPublic_len = 0;
    const char *stPublic = lua_tolstring(L, 2, &stPublic_len);
    if(stPublic == NULL)
    {
        lua_pushnumber(L, -1);
        lua_pushstring(L, "argument #2 should be string");
        return 2;
    }

    int undo_base64 = lua_toboolean(L, 3);

    RSA * r = ReadRSAPublicKey(stPublic, stPublic_len);
    if (NULL == r){
        lua_pushnumber(L, -1);
        get_ssl_error(L,"ReadRSAPublicKey");
        // lua_pushstring(L, "Read Public Key Failed");
        return 2;
    }
    int RSASIZE = RSA_size(r);

    //keysize must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based padding modes according to Official Manuals,if you want to known more details please refer to http://www.openssl.org/docs/crypto/RSA_public_encrypt.html
    int keysize = RSASIZE - 11;
    int runs = (str_in_len + keysize - 1) / keysize;
    int out_len = 0;
    char * out_buf = malloc(runs *RSASIZE);
    int i = 0;
    for (i = 0; i < runs; i++)
    {
        int block = keysize;
        if(str_in_len < keysize)
        {
            block = str_in_len;
        }
        int len = RSA_public_encrypt(block , (unsigned char *)&str_in[i*keysize], (unsigned char *)&out_buf[i*RSASIZE], r, RSA_PKCS1_PADDING);
        if (0 > len)
        {
            RSA_free(r);
            free(out_buf);
            lua_pushnumber(L, -1);
            get_ssl_error(L,"RSA_public_encrypt");
            // lua_pushstring(L, "Read Public Key Failed");
            return 2;
        }
        str_in_len -= block;
        out_len += len;
    }
    RSA_free(r);

    if (undo_base64){
        lua_pushnumber(L, 0);
        lua_pushlstring(L, out_buf, out_len);
    }
    else
    {
        int b64_buf_len = out_len * 4 / 3 + 4 + 1;
        char *b64_buf = malloc(b64_buf_len);
        Base64Encode(out_buf, out_len, b64_buf, b64_buf_len);
        lua_pushnumber(L, 0);
        lua_pushstring(L, b64_buf);
        free(b64_buf);
    }
    free(out_buf);
    return 2;
}

//the private key must be format like "-----BEGIN RSA PRIVATE KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCubeE0twrq2FTKq67mwVSFZ2d8\n...\n-----END RSA PRIVATE KEY-----\n"
//私钥解密
static int l_decrypt_pem(lua_State * L)
{
    size_t str_in_len = 0;
    const char *str_in = lua_tolstring (L, 1, &str_in_len);
    if (str_in == NULL)
    {
        lua_pushnumber(L, -1);
        lua_pushstring(L, "argument #1 should be string");
        return 2;
    }
    size_t stPrivate_len = 0;
    const char *str_private = lua_tolstring (L, 2, &stPrivate_len);
    if (str_private == NULL)
    {
        lua_pushnumber(L, -1);
        lua_pushstring(L, "argument #2 should be string");
        return 2;
    }

    int undo_base64 = lua_toboolean(L, 3);

    RSA *r = ReadRSAPrivateKey(str_private, stPrivate_len);
    if (NULL == r)
    {
        lua_pushnumber(L, -1);
        get_ssl_error(L,"ReadRSAPrivateKey");
        // lua_pushstring(L, "Read Private Key failed");
        return 2;
    }

    char *in_buf = (char *)str_in;
    int in_buf_len = str_in_len;
    int free_base64_buf = 0;

    if (!undo_base64){
        size_t b64_buf_len;
        if( (str_in_len * 3 / 4 + 1) > 65 )
        {
            b64_buf_len = str_in_len * 3 / 4 + 1;
        }
        else
        {
            b64_buf_len = 65;
        }
        char *b64_buf = malloc(b64_buf_len);
        memset(b64_buf, 0, b64_buf_len);
        int bl = Base64Decode(str_in, str_in_len, b64_buf, b64_buf_len);
        if(bl <= 0)
        {
            free(b64_buf);
            lua_pushnumber(L, -1);
            // lua_pushstring(L, "decode Base64 failed");
            get_ssl_error(L,"Base64Decode");
            return 2;
        }
        free_base64_buf = 1;
        in_buf = b64_buf;
        in_buf_len = bl;
    }


    int keysize = RSA_size(r);
    int runs = (in_buf_len + keysize - 1) / keysize;
    int i = 0;

    int out_len = 0 ;
    char *out_buf = (char *) malloc(in_buf_len);


    int succ = 1;
    for ( i = 0; i < runs; i++)
    {
        int block = keysize;
        if(in_buf_len < keysize)
        {
            block = in_buf_len;
        }
        int len = RSA_private_decrypt(block, (unsigned char *)&in_buf[i*keysize], (unsigned char *)&out_buf[out_len], r, RSA_PKCS1_PADDING);
        if (0 > len)
        {
            succ = 0;
            break;
        }
        out_len += len;
        in_buf_len -= block;
        //printf("%d\n",len);
    }

    if (succ) {
        lua_pushnumber(L, 0);
        lua_pushlstring(L, out_buf, out_len);
    }
    else
    {
        lua_pushnumber(L, -1);
        get_ssl_error(L,"RSA_private_decrypt");
    }
    RSA_free(r);
    free(out_buf);
    if (free_base64_buf) {
        free(in_buf);
    }
    return 2;
}


//私钥加密
static int l_pri_encrypt_pem(lua_State * L)
{
    size_t str_in_len = 0;

    const char *str_in = lua_tolstring(L, 1, &str_in_len);
    if(str_in == NULL)
    {
        lua_pushnumber (L, -1);
        lua_pushstring (L, "argument #1 should be string or number");
        return 2;
    }
	
    size_t pvKey_len;
    const char *pvKey = lua_tolstring(L, 2, &pvKey_len);
    if(NULL == pvKey)
    {
        lua_pushnil(L);
        lua_pushstring(L, "argument #2 should be string");
        return 2;
    }
	
    int undo_base64 = lua_toboolean(L, 3);
	
    RSA *r = ReadRSAPrivateKey(pvKey, pvKey_len);
    if (NULL == r)
    {
        lua_pushnil(L);
        get_ssl_error(L, "ReadRSAPrivateKey");
        return 2;
    }	

    int RSASIZE = RSA_size(r);

	//keysize must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based padding modes according to Official Manuals,if you want to known more details please refer to http://www.openssl.org/docs/crypto/RSA_public_encrypt.html
    int keysize = RSASIZE - 11;
    int runs = (str_in_len + keysize - 1) / keysize;
    int out_len = 0;
    char * out_buf = malloc(runs *RSASIZE);
    int i = 0;
    for (i = 0; i < runs; i++)
    {
        int block = keysize;
        if(str_in_len < keysize)
        {
            block = str_in_len;
        }	
		int result = RSA_private_encrypt(block, (unsigned char *)&str_in[i*keysize], (unsigned char *)&out_buf[i*RSASIZE], r, RSA_PKCS1_PADDING);
		if (result < 0) 
		{
			lua_pushnil(L);
			get_ssl_error(L, "RSA_private_encrypt");
			RSA_free(r);
			free(out_buf);
			return 2;		
		}
		str_in_len -= block;
		out_len += result;
	}

	RSA_free(r);	
    if (undo_base64){
        lua_pushnumber(L, 0);
        lua_pushlstring(L, out_buf, out_len);
    }	
    else
    {
        int b64_buf_len = out_len * 4 / 3 + 4 + 1;
        char *b64_buf = malloc(b64_buf_len);
        Base64Encode(out_buf, out_len, b64_buf, b64_buf_len);
        lua_pushnumber(L, 0);
        lua_pushstring(L, b64_buf);
        free(b64_buf);
    }	
	free(out_buf);
    return 2;
}

//公钥解密
static int l_pub_decrypt_pem(lua_State * L)
{
    size_t str_in_len = 0;
    const char *str_in = lua_tolstring (L, 1, &str_in_len);
    if (str_in == NULL)
    {
        lua_pushnumber(L, -1);
        lua_pushstring(L, "argument #1 should be string");
        return 2;
    }
    size_t stPublic_len = 0;
    const char *str_public = lua_tolstring (L, 2, &stPublic_len);
    if (str_public == NULL)
    {
        lua_pushnumber(L, -1);
        lua_pushstring(L, "argument #2 should be string");
        return 2;
    }

    int undo_base64 = lua_toboolean(L, 3);

    RSA *r = ReadRSAPublicKey(str_public, stPublic_len);
    if (NULL == r)
    {
        lua_pushnumber(L, -1);
        get_ssl_error(L,"ReadRSAPublicKey");
        return 2;
    }

    char *in_buf = (char *)str_in;
    int in_buf_len = str_in_len;
    int free_base64_buf = 0;

    if (!undo_base64){
        size_t b64_buf_len;
        if( (str_in_len * 3 / 4 + 1) > 65 )
        {
            b64_buf_len = str_in_len * 3 / 4 + 1;
        }
        else
        {
            b64_buf_len = 65;
        }
        char *b64_buf = malloc(b64_buf_len);
        memset(b64_buf, 0, b64_buf_len);
        int bl = Base64Decode(str_in, str_in_len, b64_buf, b64_buf_len);
        if(bl <= 0)
        {
            free(b64_buf);
            lua_pushnumber(L, -1);
            // lua_pushstring(L, "decode Base64 failed");
            get_ssl_error(L,"Base64Decode");
            return 2;
        }
        free_base64_buf = 1;
        in_buf = b64_buf;
        in_buf_len = bl;
    }

    int keysize = RSA_size(r);
    int runs = (in_buf_len + keysize - 1) / keysize;
    int i = 0;

    int out_len = 0 ;
    char *out_buf = (char *) malloc(in_buf_len);


    int succ = 1;
    for ( i = 0; i < runs; i++)
    {
        int block = keysize;
        if(in_buf_len < keysize)
        {
            block = in_buf_len;
        }
        int len = RSA_public_decrypt(block, (unsigned char *)&in_buf[i*keysize], (unsigned char *)&out_buf[out_len], r, RSA_PKCS1_PADDING);
        if (0 > len)
        {
            succ = 0;
            break;
        }
        out_len += len;
        in_buf_len -= block;
        //printf("%d\n",len);
    }

    if (succ) {
        lua_pushnumber(L, 0);
        lua_pushlstring(L, out_buf, out_len);
    }
    else
    {
        lua_pushnumber(L, -1);
        get_ssl_error(L, "RSA_public_decrypt");
    }
    RSA_free(r);
    free(out_buf);
    if (free_base64_buf) {
        free(in_buf);
    }
    return 2;
}


//私钥签名
static int l_process_signature(lua_State *L)
{
    int sha_type, sha_len;
    unsigned char * (* func_sha) (const unsigned char *, size_t, unsigned char *);

    size_t plain_buf_len;
    const char *plain_buf = lua_tolstring(L, 1, &plain_buf_len);
    if(NULL == plain_buf)
    {
        lua_pushnil(L);
        lua_pushstring(L, "argument #1 should be string");
        return 2;
    }

    size_t pvKey_len;
    const char *pvKey = lua_tolstring(L, 2, &pvKey_len);
    if(NULL == pvKey)
    {
        lua_pushnil(L);
        lua_pushstring(L, "argument #2 should be string");
        return 2;
    }

    const char *digest_name = lua_tostring(L, 3);
    if(NULL == digest_name || strcmp(digest_name, "SHA1") == 0)
    {
        sha_type = NID_sha1;
        func_sha = &SHA1;
        sha_len = SHA_DIGEST_LENGTH;
    }
    else if (strcmp(digest_name, "SHA256") == 0)
    {
        sha_type = NID_sha256;
        func_sha = &SHA256;
        sha_len = SHA256_DIGEST_LENGTH;
    }
    else if (strcmp(digest_name, "SHA512") == 0)
    {
        sha_type = NID_sha512;
        func_sha = &SHA512;
        sha_len = SHA512_DIGEST_LENGTH;
    }
    else
    {
        lua_pushnil(L);
        lua_pushstring(L, "argument #3 unsupport digest method");
        return 2;
    }

    RSA *rsa = ReadRSAPrivateKey(pvKey, pvKey_len);
    if (NULL == rsa)
    {
        lua_pushnil(L);
        get_ssl_error(L, "ReadRSAPrivateKey");
        return 2;
    }
    int sig_len = RSA_size(rsa);
    char *sig_buf = malloc(sig_len);
    if (NULL == sig_buf)
    {
        RSA_free(rsa);
        lua_pushnil(L);
        lua_pushstring(L, "malloc RSA failed");
        return 2;
    }

    unsigned char * digest_buf = malloc(sha_len);
    func_sha((unsigned char *)plain_buf, plain_buf_len, digest_buf);

    int ret =  RSA_sign(sha_type, digest_buf, sha_len,
                    (unsigned char *)sig_buf, (unsigned int *)&sig_len, rsa);
    free(digest_buf);
    if (ret != 1)
    {
        free(sig_buf);
        RSA_free(rsa);
        lua_pushnil(L);
        get_ssl_error(L, "RSASign");
        return 2;
    }

    int b64sig_len = sig_len * 4 / 3 + 4 + 1;
    char *b64sig_buf = malloc(b64sig_len);
    Base64Encode(sig_buf, sig_len, b64sig_buf, b64sig_len);

    lua_pushstring(L, b64sig_buf);

    free(b64sig_buf );
    free(sig_buf);
    RSA_free(rsa);
    return 1;
}

//公钥验签
static int l_process_check(lua_State *L)
{
    int sha_type, sha_len;
    unsigned char * (* func_sha) (const unsigned char *, size_t, unsigned char *);
    size_t signature_len, plain_buf_len, pubkey_len;
    const char *plain_buf = lua_tolstring(L, 1, &plain_buf_len);
    if(NULL == plain_buf)
    {
        lua_pushnumber(L, -1);
        lua_pushstring(L, "argument #1 should be string");
        return 2;
    }
    const char *signature = lua_tolstring(L, 2, &signature_len);
    if(NULL == signature)
    {
        lua_pushnumber(L, -1);
        lua_pushstring(L, "argument #2 should be string");
        return 2;
    }

    const char *pubkey = lua_tolstring(L, 3, &pubkey_len);
    if(NULL == pubkey)
    {
        lua_pushnumber(L, -1);
        lua_pushstring(L, "argument #3 should be string");
        return 2;
    }

    const char *digest_name = lua_tostring(L, 4);
    if(NULL == digest_name || strcmp(digest_name, "SHA1") == 0)
    {
        sha_type = NID_sha1;
        func_sha = &SHA1;
        sha_len = SHA_DIGEST_LENGTH;
    }
    else if (strcmp(digest_name, "SHA256") == 0)
    {
        sha_type = NID_sha256;
        func_sha = &SHA256;
        sha_len = SHA256_DIGEST_LENGTH;
    }
    else if (strcmp(digest_name, "SHA512") == 0)
    {
        sha_type = NID_sha512;
        func_sha = &SHA512;
        sha_len = SHA512_DIGEST_LENGTH;
    }
    else
    {
        lua_pushnil(L);
        lua_pushstring(L, "argument #4 unsupport digest method");
        return 2;
    }

    char *decoded_sign_buf = NULL;
    size_t buf_len;
    if( (strlen(signature) * 3 / 4 + 1) > 65 )
    {
        buf_len = strlen(signature) * 3 / 4 + 1;
    }
    else
    {
        buf_len = 65;
    }
    decoded_sign_buf = malloc(buf_len);
    memset(decoded_sign_buf, 0, buf_len);
    int bl = Base64Decode(signature, strlen(signature), decoded_sign_buf, buf_len);
    if(bl <= 0)
    {
        free(decoded_sign_buf);
        lua_pushnumber(L, -1);
        get_ssl_error(L,"Base64Decode");
        // lua_pushstring(L, "decode Base64 failed");
        return 2;
    }

    RSA *rsa = ReadRSAPublicKey(pubkey, pubkey_len);
    if(NULL == rsa)
    {
        free(decoded_sign_buf);
        lua_pushnumber(L, -1);
        get_ssl_error(L,"ReadRSAPublicKey");
        // lua_pushstring(L, "ReadRSAPublicKey failed");
        return 2;
    }

    unsigned char * digest_buf = malloc(sha_len);
    func_sha((unsigned char *)plain_buf, plain_buf_len, digest_buf);
    int ret = RSA_verify(sha_type, digest_buf, sha_len, (unsigned char *)decoded_sign_buf, bl, rsa);
    free(digest_buf);
    free(decoded_sign_buf);
    RSA_free(rsa);
    if(ret == 1)
    {
        //verify success
        lua_pushnumber(L, 0);
        return 1;
    }
    else
    {
        //verify failed
        lua_pushnumber(L, -1);
        get_ssl_error(L,"RSA_verify");
        // lua_pushstring(L, ERR_reason_error_string(ERR_get_error()));
        return 2;
    }
}

//以上方法要配对使用, 不能掺用