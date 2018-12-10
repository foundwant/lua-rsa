luarsa = require "luarsa"

function HexDumpString(str,spacer)
return (
	string.gsub(str,
				"(.)",
				function (c)return string.format("%02X%s",string.byte(c), spacer or "")end
				)
	)
end

local public_key  = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCubeE0twrq2FTKq67mwVSFZ2d8\n9KT+AB1gwzfQkl/fGZMWbqPbjSkYly+3JDoMUookOcDu0R5k/cucSyRVp7oUqsOr\nB/vc25ikot44jDpuWen4lg9mulB3ocwXjFymUbn5NwKdcBSeq+ABKW0VFs6POuRE\neX4vHpWy8pziYARhpQIDAQAB\n-----END PUBLIC KEY-----\n"

local private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCubeE0twrq2FTKq67mwVSFZ2d89KT+AB1gwzfQkl/fGZMWbqPb\njSkYly+3JDoMUookOcDu0R5k/cucSyRVp7oUqsOrB/vc25ikot44jDpuWen4lg9m\nulB3ocwXjFymUbn5NwKdcBSeq+ABKW0VFs6POuREeX4vHpWy8pziYARhpQIDAQAB\nAoGAPgQ5LunpisfxlcFmxQp1x5yVMds1kk1uJIokHRb92S+ZmT8rKRNOSjzurRnH\nPbxW+zxBeWeGe/e0XdRljcK9qKbRo3z2yVxv2a6OH3o87m6KuK3hPgWlJO9T0F7o\nh5Uab6bO60vKmt5T/6vLiyE7ZDn7wIBy8dflm8KAYe5NwaECQQDiiPgD1oiXDrJU\nQqg9YQHolLT5p6WOIkd4qdOs/ep3rnI8N7ZRIFqVQuy159O/RYrEXfbpCzQPwjnZ\n46xDotHZAkEAxR3r/1HVILK0qBAqKT+dNQ8AhRTcgjQ/E0uOaLcds/FvyL37Osuh\nTMHc+14+EgRWa1cnZ8ha0b8NeFmI67PirQJAQuqQ0Jlrqat2s/sotVDVfn2G5ARI\nnC62DAemdoBe5VGLfww598bl2xd00tsTKnoBXrYe/IIJs+n8qsddGHGdKQJBALkE\nTuFFpDCezGb7VTeGWD7XJ/vCCv/Dnniz8KVlS2H8+pmHiOo0+9+aD5t5Z/VtUNhL\n49bL/kLlevU9xQDHxbkCQQCHyz1ubrFWxtkAlUAeNBjK1v5V9UKHtTyghn86hZEC\niGm9GLF1uY3fFxFlI/DKi+NZJRDP3ulyJLYTNQ6qjEBG\n-----END RSA PRIVATE KEY-----\n"

local plain_text = "this is the plain text"
print("plain text:\n  ".. plain_text .. "\n")

local ret, msg = luarsa.encrypt_pem(plain_text, public_key)
if ret == 0 then
	print("encrypt success, encrypted text:\n  " .. msg .. "\n")
else
	error("encrypt failed：" .. msg .. "\n")
	return 
end


local ret, msg1=luarsa.decrypt_pem(msg, private_key)
if ret < 0 then
	error("decrypt error,:" .. msg1 .. "\n")
	return
else
	print("decrypt success, plain text:\n ".. msg1 .. "\n")
	if msg1 == plain_text then
		print("Ok, the plaintext equal decrypted plaintext!")
	else
		error("Sorry, the plaintext not equal decrypted plaintext!")
	end
end

