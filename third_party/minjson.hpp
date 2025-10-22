#pragma once
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>

namespace minjson {
    struct value {
        enum kind { STR, NUM, BOOL, ARR, OBJ, NIL } k = NIL;
        std::string s; double n=0; bool b=false;
        std::vector<value> a;
        std::map<std::string, value> o;
        static value string(const std::string& s){ value v; v.k=STR; v.s=s; return v; }
        static value number(double n){ value v; v.k=NUM; v.n=n; return v; }
        static value boolean(bool b){ value v; v.k=BOOL; v.b=b; return v; }
        static value array(){ value v; v.k=ARR; return v; }
        static value object(){ value v; v.k=OBJ; return v; }
        static value null(){ value v; v.k=NIL; return v; }
        value& operator[](const std::string& key){ k=OBJ; return o[key]; }
        void push(const value& v){ if (k!=ARR) k=ARR; a.push_back(v); }
        static std::string esc(const std::string& in){
            std::ostringstream o; o<<'"';
            for(char c: in){
                switch(c){
                    case '\"': o<<"\\\""; break;
                    case '\\': o<<"\\\\"; break;
                    case '\b': o<<"\\b"; break;
                    case '\f': o<<"\\f"; break;
                    case '\n': o<<"\\n"; break;
                    case '\r': o<<"\\r"; break;
                    case '\t': o<<"\\t"; break;
                    default:
                        if ((unsigned char)c < 0x20) { o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(int)(unsigned char)c; }
                        else o<<c;
                }
            }
            o<<'"'; return o.str();
        }
        std::string dump(int indent=2, int level=0) const {
            std::ostringstream o;
            switch(k){
                case STR: o<<esc(s); break;
                case NUM: o<<std::fixed<<std::setprecision(0)<<n; break;
                case BOOL: o<<(b?"true":"false"); break;
                case NIL: o<<"null"; break;
                case ARR: {
                    o<<"[";
                    for(size_t i=0;i<a.size();++i){
                        if (i) o<<",";
                        o<<"\n"<<std::string((level+1)*indent,' ')<<a[i].dump(indent, level+1);
                    }
                    if (!a.empty()) o<<"\n"<<std::string(level*indent,' ');
                    o<<"]";
                } break;
                case OBJ: {
                    o<<"{";
                    bool first=true;
                    for (auto& kv : o){
                        if (!first) o<<",";
                        o<<"\n"<<std::string((level+1)*indent,' ')<<esc(kv.first)<<": "<<kv.second.dump(indent, level+1);
                        first=false;
                    }
                    if (!o.empty()) o<<"\n"<<std::string(level*indent,' ');
                    o<<"}";
                } break;
            }
            return o.str();
        }
    };
}
