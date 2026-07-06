#include "hollowdet/api.h"
#include "hollowdet/json.h"
#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <map>
#include <set>
#include <sstream>

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
    o<<"{\n";
    o<<"  \"version\": 1,\n";
    o<<"  \"$schema\": \"https://hollowdetect/schema/anomaly.json\",\n";
    o<<"  \"items\": [\n";
    for (size_t i=0;i<v.size();++i){
        auto& a=v[i];
        o<<"    {\n";
        o<<"      \"version\": 1,\n";
        o<<"      \"pid\": "<<a.pid<<",\n";
        o<<"      \"process\": "<<JsonString(a.process)<<",\n";
        o<<"      \"base\": "<<JsonString(ToHex64(a.base))<<",\n";
        o<<"      \"allocation_base\": "<<JsonString(ToHex64(a.allocation_base))<<",\n";
        o<<"      \"size\": "<<a.size<<",\n";
        o<<"      \"type\": "<<JsonString(a.type)<<",\n";
        o<<"      \"protect\": "<<JsonString(a.protect)<<",\n";
        o<<"      \"mapped_path\": "<<JsonString(a.mapped_path)<<",\n";
        o<<"      \"module_path\": "<<JsonString(a.module_path)<<",\n";
        o<<"      \"section_name\": "<<JsonString(a.section_name)<<",\n";
        o<<"      \"section_flags\": "<<JsonString(a.section_flags)<<",\n";
        o<<"      \"is_pe\": "<<(a.is_pe?"true":"false")<<",\n";
        o<<"      \"reasons\": [";
        for(size_t j=0;j<a.reasons.size();++j){ if(j) o<<", "; o<<JsonString(a.reasons[j]); }
        o<<"],\n";
        o<<"      \"thread_ids\": [";
        for(size_t j=0;j<a.thread_ids.size();++j){ if(j) o<<", "; o<<a.thread_ids[j]; }
        o<<"],\n";
        o<<"      \"severity\": "<<JsonString(a.severity)<<",\n";
        o<<"      \"fingerprint\": "<<JsonString(a.fingerprint)<<"\n";
        o<<"    }";
        if (i+1<v.size()) o<<",";
        o<<"\n";
    }
    o<<"  ]\n";
    o<<"}\n";
    if (path.empty()){ std::cout<<o.str(); return 0; }
    if (!WriteTextFile(path, o.str())){ std::cerr<<"write failed\n"; return 2; }
    return 0;
}

static int SeverityRank(const std::string& value) {
    static const std::map<std::string,int> rank{{"none",0},{"low",1},{"medium",2},{"high",3},{"critical",4}};
    auto it = rank.find(value);
    return it == rank.end() ? -1 : it->second;
}

static std::set<std::string> FingerprintsFromReport(const std::wstring& path) {
    std::string text;
    std::set<std::string> out;
    if (!ReadTextFile(path, text)) {
        return out;
    }
    size_t pos = 0;
    while (pos < text.size()) {
        size_t key = text.find("\"fingerprint\"", pos);
        if (key == std::string::npos) {
            break;
        }
        std::string_view tail(text.data() + key, text.size() - key);
        auto fp = JsonFindString(tail, "fingerprint");
        if (fp && !fp->empty()) {
            out.insert(*fp);
        }
        pos = key + 13;
    }
    return out;
}

static int RenderSnapshotDiff(const std::set<std::string>& old_items, const std::set<std::string>& new_items) {
    std::vector<std::string> added;
    std::vector<std::string> removed;
    std::set_difference(new_items.begin(), new_items.end(), old_items.begin(), old_items.end(), std::back_inserter(added));
    std::set_difference(old_items.begin(), old_items.end(), new_items.begin(), new_items.end(), std::back_inserter(removed));

    std::ostringstream out;
    out << "{\n";
    out << "  \"version\": 1,\n";
    out << "  \"old_count\": " << old_items.size() << ",\n";
    out << "  \"new_count\": " << new_items.size() << ",\n";
    out << "  \"added_count\": " << added.size() << ",\n";
    out << "  \"removed_count\": " << removed.size() << ",\n";
    out << "  \"added\": [";
    for (size_t i = 0; i < added.size(); ++i) {
        if (i != 0) out << ", ";
        out << JsonString(added[i]);
    }
    out << "],\n";
    out << "  \"removed\": [";
    for (size_t i = 0; i < removed.size(); ++i) {
        if (i != 0) out << ", ";
        out << JsonString(removed[i]);
    }
    out << "]\n";
    out << "}\n";
    std::cout << out.str();
    return (!added.empty() || !removed.empty()) ? 1 : 0;
}

static int CmdScan(int argc, wchar_t** argv){
    ScanOptions opt; std::wstring jsonOut, exFile, blFile;
    std::wstring fail = L"medium";
    for (int i=2;i<argc;i++){
        std::wstring a=argv[i];
        if (a==L"--pid" && i+1<argc) opt.pid = wcstoul(argv[++i], NULL, 10);
        else if (a==L"--all") opt.all = true;
        else if (a==L"--json" && i+1<argc) jsonOut = argv[++i];
        else if (a==L"--evidence" && i+1<argc) opt.evidence_dir = argv[++i];
        else if (a==L"--max-dump-bytes" && i+1<argc) opt.max_dump_bytes = wcstoul(argv[++i], NULL, 10);
        else if (a==L"--exceptions" && i+1<argc) exFile = argv[++i];
        else if (a==L"--baseline" && i+1<argc) blFile = argv[++i];
        else if (a==L"--fail-on" && i+1<argc) fail = argv[++i];
        else if (a==L"--quiet") opt.quiet = true;
    }
    if (!LoadExceptions(exFile, opt.ignore_proc, opt.ignore_paths)){
        std::cerr<<"bad exceptions file\n"; return 2;
    }
    if (!blFile.empty()){
        std::wstring app;
        if (!LoadBaseline(blFile, app, opt.baseline_fps)){ std::cerr<<"bad baseline file\n"; return 2; }
    }

    std::vector<Anomaly> items;
    ScanSystem(opt, items);
    if (!opt.quiet){
        for (auto& a: items){
            std::wcout<<L"[ "<<(a.severity=="high"?L"H":(a.severity=="medium"?L"M":L"L"))<<L" ] PID="<<a.pid<<L" "<<a.process<<L" "<<a.mapped_path<<L" "<<Utf8ToWide(a.type)<<L" "<<Utf8ToWide(a.protect)<<L" "<<Utf8ToWide(a.fingerprint)<<L"\n";
        }
    }
    int rc = RenderJson(items, jsonOut);
    // fail-on
    int thr = SeverityRank(WideToUtf8(fail));
    if (thr < 0){ std::cerr<<"bad --fail-on value\n"; return 2; }
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
    for (auto& a: items){ if (a.process == app) fps.push_back(Utf8ToWide(a.fingerprint)); }
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
    auto old_items = FingerprintsFromReport(argv[3]);
    auto new_items = FingerprintsFromReport(argv[4]);
    return RenderSnapshotDiff(old_items, new_items);
}

static int Main(int argc, wchar_t** argv){
    if (argc<2){ Usage(); return 2; }
    std::wstring cmd = argv[1];
    if (cmd==L"self-check"){ std::wcout<<L"OK\n"; return 0; }
    if (cmd==L"dump-schema"){
        std::string schema;
        if (!ReadTextFile(L"schema\\anomaly.schema.json", schema)){ std::wcerr<<L"schema not found\n"; return 2; }
        std::cout<<schema; return 0;
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

#ifdef _MSC_VER
int wmain(int argc, wchar_t** argv){
    return Main(argc, argv);
}
#else
int main(int argc, char** argv){
    std::vector<std::wstring> wide;
    std::vector<wchar_t*> args;
    wide.reserve(static_cast<size_t>(argc));
    args.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        wide.push_back(Utf8ToWide(argv[i]));
    }
    for (auto& arg : wide) {
        args.push_back(arg.data());
    }
    return Main(argc, args.data());
}
#endif
