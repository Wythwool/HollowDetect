#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "Crypt32.lib")

namespace hollow {

std::string ToHex64(uint64_t v){
    std::ostringstream o; o<<"0x"<<std::hex<<std::nouppercase<<v; return o.str();
}

std::string ProtectToString(DWORD p){
    bool r=false,w=false,x=false;
    if (p & PAGE_EXECUTE) x=true;
    if (p & PAGE_EXECUTE_READ) {x=true; r=true;}
    if (p & PAGE_EXECUTE_READWRITE) {x=true; r=true; w=true;}
    if (p & PAGE_EXECUTE_WRITECOPY) {x=true; r=true; w=true;}
    if (p & PAGE_READONLY) r=true;
    if (p & PAGE_READWRITE) {r=true; w=true;}
    if (p & PAGE_WRITECOPY) {r=true; w=true;}
    std::string s; s += (r?'R':'-'); s += (w?'W':'-'); s += (x?'X':'-');
    if (p & PAGE_GUARD) s += 'G';
    if (p & PAGE_NOACCESS) s = "NOACC";
    return s;
}

static bool Sha256(const unsigned char* d, size_t n, unsigned char out[32]){
    HCRYPTPROV hProv=0; if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;
    HCRYPTHASH hHash=0; if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { CryptReleaseContext(hProv,0); return false; }
    if (!CryptHashData(hHash, d, (DWORD)n, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv,0); return false; }
    DWORD sz=32; if (!CryptGetHashParam(hHash, HP_HASHVAL, out, &sz, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv,0); return false; }
    CryptDestroyHash(hHash); CryptReleaseContext(hProv,0); return true;
}

std::string Sha256Str(const std::string& data){
    unsigned char h[32]; if (!Sha256((const unsigned char*)data.data(), data.size(), h)) return std::string();
    std::ostringstream o; for(int i=0;i<32;i++) o<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)h[i];
    return o.str();
}

} // namespace hollow
