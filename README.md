```python
import time
import hmac
import base64
import struct
import hashlib

def get_hotp_token(secret, intervals_no, digits=6):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    token = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % (10**digits)
    return str(token).zfill(digits)

def get_totp_token(secret, time_step=30, digits=6):
    return get_hotp_token(secret, int(time.time() / time_step), digits)

# 테스트용 시크릿 키 (실제 운영에서는 보안이 강화된 키 사용)
secret_key = "JBSWY3DPEHPK3PXP"

# 현재 OTP 생성
otp = get_totp_token(secret_key)
print("현재 OTP:", otp)
```
HOTP HMAC을 기반으로한 한번제공되는 패스워드 생성
시크릿키 <- base32로 인코딩
intervals_no <- otp 생성 지점
digits : otp 자릿수를 설정합니다. 기본값은 6자리로 줬습니다.  

base32 인코딩 된 시크릿 키를 디코딩하고
intervals_no 값을 8바이트 64비트 빅 엔디안 형식으로 변환한 후 
hmac-sha1 해시 계산하고, 다이제스트의 마지막 바이트에서 4비트를 가져옵니다.

otp를 계산하고 지정된 자릿수로 변환해주고

