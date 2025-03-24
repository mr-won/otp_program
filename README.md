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
