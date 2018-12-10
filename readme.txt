
该模块导出了6个函数
    公钥加密/私钥解密
    私钥加密/公钥解密
    私钥签名/公钥验签

(1)encrypt_pem
    描述：使用公钥对明文进行rsa加密
    语法：
        local ret,  msg = encrypt_pem(plain_text,  public_key,  no_base64_flag)
    输入
        plain_text: 待加密明文
        public_key: 公钥
        no_base64_flag(bool)：该参数为可选, 表示加密后是否对密文进行base64编码, 默认为false, 即对密文进行base64编码, 反之则不进行base64编码
    输出
        当 ret=0 时, 表示加密成功, msg表示密文
        当 ret<0 时, 表示加密失败, msg为错误信息

(2)decrypt_pem
    描述：使用私钥对密文进行rsa解密
    语法：
        local ret,  msg = decrypt_pem(encrypted_text,  private_key,  no_base64_flag)
    输入
        encrypted_text: 待解密密文
        private_key: 私钥
        base64_flag：该参数为可选, 表示是否先对密文进行base64解密, 默认为false, 即对密文进行base64解码后再解密, 否则直接进行解密。
    输出
        当 ret=0 时, 表示解密成功, msg表示明文
        当 ret<0 时, 表示解密成功, msg为错误信息

(3)process_check
    描述：校验签名
    语法：
        local ret,  error_msg = process_check(plain_text,  signed_text,  public_key,  digest)
    输入
        plain_text: 明文
        signed_text: 签名串
        public_key: 公钥
        digest: 散列算法, 可选, 默认为"SHA1", 支持 "SHA1",  "SHA256",  "SHA512"
    输出
        ret：ret=0表示签名正确, 小于0表示签名不正确
        error_msg：当ret小于0时表示错误信息

(4)process_signature
    描述：生成签名串
    语法：
        local signed_text,  error_msg = process_signature(plain_text,  private_key,  digest)
    输入
        plain_text: 明文
        private_key: 私钥
        digest: 散列算法, 可选, 默认为"SHA1", 支持 "SHA1",  "SHA256",  "SHA512"
    输出
        signed_text：签名串, 当签名失败时, 该值为 nil
        error_msg：当signed_text为 nil时表示错误信息

(5)pri_encrypt_pem : 
    描述：使用私钥对明文进行rsa加密
    语法：
        local ret,  msg = pri_encrypt_pem(plain_text,  public_key,  no_base64_flag)
    输入
        plain_text: 待加密明文
        public_key: 公钥
        no_base64_flag(bool)：该参数为可选, 表示加密后是否对密文进行base64编码, 默认为false, 即对密文进行base64编码, 反之则不进行base64编码
    输出
        当 ret=0 时, 表示加密成功, msg表示密文
        当 ret<0 时, 表示加密失败, msg为错误信息

(6)pub_decrypt_pem
    描述：使用公钥对密文进行rsa解密
    语法：
        local ret,  msg = decrypt_pem(encrypted_text,  private_key,  no_base64_flag)
    输入
        encrypted_text: 待解密密文
        private_key: 私钥
        no_base64_flag:该参数为可选, 表示是否先对密文进行base64解密, 默认为false, 即对密文进行base64解码后再解密, 否则直接进行解密。
    输出
        当 ret=0 时, 表示解密成功, msg表示明文
        当 ret<0 时, 表示解密成功, msg为错误信息
具体的用法请参照 示例 test_sign_check.lua 和 test_encrypt_decrypt.lua


###############
[编译安装]
0. 首先确保系统有openssl开发环境
    yum install -y openssl libssl-dev

1. 执行make指令,  编译得到luarsa.so

2. 把luarsa.so放到工程文件夹conf同级别的目录lualib下面即可

可以执行 $make test 来测试生成的库是否生效

###############
[在线升级提醒]
如果nginx在init_by_lua中载入.so,  如
    luarsa = require "luarsa"
reload可能导致master crash
升级时建议先不使用.so(注释掉, 或者在使用时再require), reload一次
再替换so文件, 再reload,  之后可以放入init_by_lua里
建议动态lua库不放到init_by_lua里, 即不载入master进程