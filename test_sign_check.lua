--process_signature 
luarsa = require "luarsa"

local pvKey = 
		"-----BEGIN RSA PRIVATE KEY-----\n"..
		"MIICXAIBAAKBgQDXQbNg6m89v+xi3U/91nE5UueIDfszh/yE/c7/GENvAcZNGbFj\n"..
		"hfbUxknsnmqUB2gziJosWxBALK/IotBAKgUx+HztppH4UaZiLCdJGRPjvCK/miiY\n"..
		"LiAAULLGZB98mkyC99iK56K3m85oiKNPUAL4XD+ra9J4vHP9H7UyQPVllQIDAQAB\n"..
		"AoGAbMoVwGt7YTf4Xlb/sIiKnLAbuBVo2bhmlUg5L4+xtQ6ujBTqJCR2hT7Z6a5+\n"..
		"quW7ciAd20ECy4xKIxq2KVeTW6ndlAX0noLVl27GJ1TV37eErJ6jqPBoaq8OP3nG\n"..
		"CQyJ8jUhrPXe68ni0DKX37D/528MT8C6OgG2PgQzGF+mNkECQQD/U5W9fbVKtdrp\n"..
		"07Gz0eRfq6hfaYUMO6K3BH3eDevbM0tYYuXrwq1v3oayF+/3op3o+I+RlnEOxgND\n"..
		"BDnK7+I5AkEA19MOxEyyBRF/iu+bs1+Mh0Pwa3PQHxVrv5uHVFQbE2IgfUhl7yd1\n"..
		"VfJ+cpud2cNT25sWAFawevW/6Bc4h1huPQJAaIv+LWgS2rOaHtKa2emg3He6as8X\n"..
		"NooYt130d/81Sz02pcthH+dIAx2YA8Z/cOO6SxG0H8X9JzJ3VXKeg3U0KQJAM2WA\n"..
		"s8Cr+EcFf5m2E45ikefc/knTO0PHqBaqsKti00fgAtXV6JEWAUTBVhu3CJ/afYa+\n"..
		"Q5BhcLbLX8L/5ENr5QJBAIptNfmM5BpEnjNMWwFJd5THZUAAcU3x0pcII9e/q0JF\n"..
		"eWjLA2ep4o0KBACNlvSPWFx6FMMKsPOQXtGAY50Qfzo=\n"..
		"-----END RSA PRIVATE KEY-----";	
		
local pubKey =         
		"-----BEGIN PUBLIC KEY-----\n"..
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXQbNg6m89v+xi3U/91nE5UueI\n"..
		"Dfszh/yE/c7/GENvAcZNGbFjhfbUxknsnmqUB2gziJosWxBALK/IotBAKgUx+Hzt\n"..
		"ppH4UaZiLCdJGRPjvCK/miiYLiAAULLGZB98mkyC99iK56K3m85oiKNPUAL4XD+r\n"..
		"a9J4vHP9H7UyQPVllQIDAQAB\n"..
		"-----END PUBLIC KEY-----\n";
		
local plain_text = "test process_signature and process_check"
print("plain test:\n  " .. plain_text .. "\n")

local signed_text, err_msg = luarsa.process_signature(plain_text, pvKey)
if not signed_text then
	error("process_signature failed:"..err_msg)
	return
else
	print("process_signature success, signed text:\n  " .. signed_text .. "\n")
end

local succ, err_msg = luarsa.process_check(plain_text, signed_text, pubKey)
if succ < 0 then
	error("process_check error:"..err_msg)
else
	print("process_check success!")
end
