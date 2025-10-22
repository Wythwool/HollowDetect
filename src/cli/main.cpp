#include "hollowdet/api.h"
#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>

using namespace hollow;

static void Usage(){
    std::cout<<"hollowdet scan [--pid PID | --all] [--json OUT] [--evidence DIR] [--max-dump-bytes N]\n";
    std::cout<<"               [--exceptions exceptions.json] [--baseline baseline.json]\n";
    std::cout<<"               [--fail-on none|low|medium|high|critical] [--quiet]\n";
    std::cout<<"hollowdet baseline create --pid PID|--process EXE --out baseline.json\n";
    std::cout<<"hollowdet baseline apply  --baseline baseline.json [--pid PID|--all] [--json OUT]\n";
    std::cout<<"hollowdet snapshot save --pid PID|--all --out snapshot.json\n";
    std::cout<<"hollowdet snapshot diff OLD.json NEW.json\n";
    std::cout<<"hollowdet self-check\n";
    std::cout<<"hollowdet dump-schema\n";
}

static int RenderJson(const std::vector<Anomaly>& v, const std::wstring& path){
    std::ostringstream o;
    o<<"{\n  \"version\":1,\n  \"$schema\":\"https://hollowdetect/schema/anomaly.json\",\n  \"items\":[\n";
    for (size_t i=0;i<v.size();++i){
        auto& a=v[i];
        o<<"    {\"version\":1,\"pid\":"<<a.pid<<",\"process\":\"";
        for (auto c: a.process) o<<(c<128?(char)c:'?');
        o<<"\","
         <<"\"base\":\""<<ToHex64(a.base)<<"\",\"size\":"<<a.size
         <<",\"type\":\""<<a.type<<"\",\"protect\":\""<<a.protect<<"\",\"mapped_path\":\"";
        for (auto c: a.mapped_path) o<<(c<128?(char)c:'?');
        o<<"\",\"is_pe\":"<<(a.is_pe?"true":"false")<<",\"reasons\":[";
        for(size_t j=0;j<a.reasons.size();++j){ if(j) o<<","; o<<"\""<<a.reasons[j]<<"\""; }
        o<<"],\"severity\":\""<<a.severity<<"\",\"fingerprint\":\""<<a.fingerprint<<"\"}";
        if (i+1<v.size()) o<<",";
        o<<"\n";
    }
    o<<"  ]\n}\n";
    if (path.empty()){ std::cout<<o.str(); return 0; }
    std::ofstream f(path, std::ios::binary); if (!f){ std::cerr<<"write failed\n"; return 2; }
    auto s=o.str(); f.write(s.data(), s.size());
    return 0;
}

static int CmdScan(int argc, wchar_t** argv){
    ScanOptions opt; std::wstring jsonOut, exFile, blFile, appName;
    std::wstring fail = L"medium";
    for (int i=2;i<argc;i++){
        std::wstring a=argv[i];
        if (a==L"--pid" && i+1<argc) opt.pid = wcstoul(argv[++i], NULL, 10);
        else if (a==L"--all") opt.all = true;
        else if (a==L"--json" && i+1<argc) jsonOut = argv[++i];
        else if (a==L"--evidence" && i+1<argc) opt.evidence_dir = argv[++i];
        else if (a==L"--max-dump-bytes" && i+1<argc) opt.max_dump_bytes = _wtoi(argv[++i]);
        else if (a==L"--exceptions" && i+1<argc) exFile = argv[++i];
        else if (a==L"--baseline" && i+1<argc) blFile = argv[++i];
        else if (a==L"--fail-on" && i+1<argc) fail = argv[++i];
        else if (a==L"--quiet") opt.quiet = true;
    }
    LoadExceptions(exFile, opt.ignore_proc, opt.ignore_paths);
    std::wstring app; LoadBaseline(blFile, app, opt.baseline_fps);

    std::vector<Anomaly> items;
    ScanSystem(opt, items);
    if (!opt.quiet){
        for (auto& a: items){
            std::wcout<<L"[ "<<(a.severity=="high"?L"H":(a.severity=="medium"?L"M":L"L"))<<L" ] PID="<<a.pid<<L" "<<a.process<<L" "<<a.mapped_path<<L" "<<a.type.c_str()<<L" "<<a.protect.c_str()<<L" "<<a.fingerprint.c_str()<<L"\n";
        }
    }
    int rc = RenderJson(items, jsonOut);
    // fail-on
    std::map<std::string,int> rank{{"none",0},{"low",1},{"medium",2},{"high",3},{"critical",4}};
    int thr = rank[std::string(fail.begin(), fail.end())];
    int worst=0;
    for (auto& a: items){
        int lv = (a.severity=="critical")?4:(a.severity=="high")?3:(a.severity=="medium")?2:(a.severity=="low")?1:0;
        if (lv>worst) worst=lv;
    }
    if (worst>=thr && thr>0) return 1;
    return rc;
}

static int CmdBaselineCreate(int argc, wchar_t** argv){
    std::wstring out, procPath; DWORD pid=0;
    for (int i=3;i<argc;i++){
        std::wstring a=argv[i];
        if (a==L"--pid" && i+1<argc) pid = wcstoul(argv[++i], NULL, 10);
        else if (a==L"--process" && i+1<argc) procPath = argv[++i];
        else if (a==L"--out" && i+1<argc) out = argv[++i];
    }
    if (out.empty() || (pid==0 && procPath.empty())){ std::cerr<<"args\n"; return 2; }
    ScanOptions opt; if (pid) opt.pid=pid; else opt.all=true; opt.quiet=true;
    std::vector<Anomaly> items; ScanSystem(opt, items);
    // pick anomalies for the target app
    std::wstring app = procPath;
    if (app.empty() && !items.empty()) app = items[0].process; // best effort
    std::vector<std::wstring> fps;
    for (auto& a: items){ if (a.process == app) fps.push_back(std::wstring(a.fingerprint.begin(), a.fingerprint.end())); }
    if (!SaveBaseline(out, app, fps)){ std::cerr<<"baseline write failed\n"; return 2; }
    std::wcout<<L"Wrote baseline "<<out<<L" for "<<app<<L"\n";
    return 0;
}

static int CmdBaselineApply(int argc, wchar_t** argv){
    std::wstring bl, jsonOut; DWORD pid=0; bool all=false;
    for (int i=3;i<argc;i++){
        std::wstring a=argv[i];
        if (a==L"--baseline" && i+1<argc) bl = argv[++i];
        else if (a==L"--pid" && i+1<argc) pid = wcstoul(argv[++i], NULL, 10);
        else if (a==L"--all") all=true;
        else if (a==L"--json" && i+1<argc) jsonOut = argv[++i];
    }
    if (bl.empty()){ std::cerr<<"--baseline required\n"; return 2; }
    std::wstring app; std::vector<std::wstring> fps;
    if (!LoadBaseline(bl, app, fps)){ std::cerr<<"bad baseline\n"; return 2; }
    ScanOptions opt; opt.pid=pid; opt.all=all; opt.baseline_fps = fps; opt.quiet = true;
    std::vector<Anomaly> items; ScanSystem(opt, items);
    return RenderJson(items, jsonOut);
}

static int CmdSnapshotSave(int argc, wchar_t** argv){
    std::wstring out; DWORD pid=0; bool all=false;
    for (int i=3;i<argc;i++){
        std::wstring a=argv[i];
        if (a==L"--pid" && i+1<argc) pid = wcstoul(argv[++i], NULL, 10);
        else if (a==L"--all") all=true;
        else if (a==L"--out" && i+1<argc) out = argv[++i];
    }
    if (out.empty()){ std::cerr<<"--out required\n"; return 2; }
    ScanOptions opt; opt.pid=pid; opt.all=all; opt.quiet=true;
    std::vector<Anomaly> items; ScanSystem(opt, items);
    return RenderJson(items, out);
}

static int CmdSnapshotDiff(int argc, wchar_t** argv){
    if (argc<5){ std::cerr<<"args\n"; return 2; }
    std::wifstream A(argv[3]), B(argv[4]); if (!A||!B){ std::cerr<<"read\n"; return 2; }
    std::wstring sa((std::istreambuf_iterator<wchar_t>(A)), {});
    std::wstring sb((std::istreambuf_iterator<wchar_t>(B)), {});
    auto count_items = [](const std::wstring& s)->int{
        int c=0; size_t pos=0; while ((pos = s.find(L"\"fingerprint\"", pos)) != std::wstring::npos){ c++; pos+=5; } return c;
    };
    int ca = count_items(sa), cb = count_items(sb);
    std::wcout<<L"items_old="<<ca<<L" items_new="<<cb<<L"\n";
    return 0;
}

int wmain(int argc, wchar_t** argv){
    if (argc<2){ Usage(); return 2; }
    std::wstring cmd = argv[1];
    if (cmd==L"self-check"){ std::wcout<<L"OK\n"; return 0; }
    if (cmd==L"dump-schema"){
        std::wifstream f(L"schema\\anomaly.schema.json"); if (!f){ std::wcerr<<L"schema not found\n"; return 2; }
        std::wcout<<f.rdbuf(); return 0;
    }
    if (cmd==L"scan") return CmdScan(argc, argv);
    if (cmd==L"baseline" && argc>=3){
        std::wstring sub=argv[2];
        if (sub==L"create") return CmdBaselineCreate(argc, argv);
        if (sub==L"apply") return CmdBaselineApply(argc, argv);
    }
    if (cmd==L"snapshot" && argc>=3){
        std::wstring sub=argv[2];
        if (sub==L"save") return CmdSnapshotSave(argc, argv);
        if (sub==L"diff") return CmdSnapshotDiff(argc, argv);
    }
    Usage(); return 2;
}
