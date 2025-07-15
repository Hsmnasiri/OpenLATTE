/* LatteTrace.java  –  Ghidra 11.3.2 PUBLIC */
//@category Latte
//@import ghidra.app.decompiler.HighFunction
//@import ghidra.app.decompiler.HighCall

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.net.URI;
import java.net.http.*;
import java.util.*;

import com.google.gson.Gson;

/* tiny records */
record ExtParam(Function fn,int idx){}
record VD(ExtParam sink,Address call,String arg){}
record CallChain(List<Address> pcs){}
record CDF(ExtParam src,VD dst,CallChain cc){}

public class LatteTrace extends GhidraScript{

    /* containers */
    private final List<Function> externals=new ArrayList<>();
    private final Set<ExtParam>  sinks=new HashSet<>();
    private final List<VD>       vds=new ArrayList<>();
    private final List<CallChain> ccs=new ArrayList<>();
    private final Set<ExtParam>  sources=new HashSet<>();
    private final List<CDF>      cdfs=new ArrayList<>();

    /* http + cache */
    private static final String URL="http://127.0.0.1:8123/check";
    private static final HttpClient HTTP=HttpClient.newHttpClient();
    private static final Gson  GSON=new Gson();
    private final Map<String,Map<Integer,Boolean>> sinkCache=new HashMap<>();
    private final Map<String,Map<Integer,Boolean>> srcCache =new HashMap<>();

    /* run */
    @Override public void run() throws Exception{
        println("▶ LATTE Trace – start");
        extractExternals();
        classify("sink");
        collectVDs();
        buildChains();
        classify("source");
        buildCDFs();
        println("✔ CDFs found: "+cdfs.size());
        for(CDF c:cdfs) println(render(c));
    }

    /* externals */
    private void extractExternals(){
        for(Function f: currentProgram.getFunctionManager().getFunctions(true))
            if(f.isExternal()) externals.add(f);
        println("  · externals = "+externals.size());
    }

    /* LLM */
    private void classify(String mode){
        for(Function f:externals){
            for(int i=0;i<f.getParameterCount();i++)
                if(ask(f.getName(),mode,i))
                    (mode.equals("sink")?sinks:sources).add(new ExtParam(f,i));
        }
        println("  · "+mode+"s = "+(mode.equals("sink")?sinks.size():sources.size()));
    }
    private boolean ask(String fn,String mode,int idx){
        var cache=mode.equals("sink")?sinkCache:srcCache;
        cache.computeIfAbsent(fn,k->new HashMap<>());
        if(!cache.get(fn).containsKey(idx)){
            try{
                String body=GSON.toJson(Map.of("func",fn,"mode",mode));
                HttpRequest rq=HttpRequest.newBuilder()
                        .uri(URI.create(URL))
                        .header("Content-Type","application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build();
                var rsp=HTTP.send(rq,HttpResponse.BodyHandlers.ofString());
                @SuppressWarnings("unchecked")
                var res=(Map<String,Object>)GSON.fromJson(rsp.body(),Map.class);
                boolean ok=Boolean.TRUE.equals(res.get("is_true"));
                @SuppressWarnings("unchecked")
                List<Double> ps=(List<Double>)res.get("params");
                for(int i=0;i<Math.max(idx+1,10);i++)
                    cache.get(fn).put(i, ok&&ps.contains((double)(i+1)));
            }catch(Exception e){ cache.get(fn).put(idx,false); }
        }
        return cache.get(fn).get(idx);
    }

    /* VDs */
    private void collectVDs(){
        for(ExtParam s:sinks)
            for(Address call:callSites(s.fn()))
                vds.add(new VD(s,call,"arg"+s.idx()));
        println("  · VDs = "+vds.size());
    }
    private List<Address> callSites(Function callee){
        List<Address> out=new ArrayList<>();
        for(var r: currentProgram.getReferenceManager()
                .getReferencesTo(callee.getEntryPoint()))
            if(r.getReferenceType().isCall()) out.add(r.getFromAddress());
        return out;
    }

    /* chains */
    private void buildChains(){
        for(VD vd:vds) ccs.add(new CallChain(slice(vd.call())));
        println("  · CCs = "+ccs.size());
    }
    private List<Address> slice(Address start){
        List<Address> chain=new ArrayList<>();
        AddressSet seen=new AddressSet();
        Deque<Address> dq=new ArrayDeque<>(List.of(start));
        while(!dq.isEmpty()){
            Address cur=dq.pop();
            if(seen.contains(cur)) continue;
            seen.add(cur); chain.add(cur);
            Instruction ins=getInstructionAt(cur);
            if(ins==null) continue;
            if(ins.getFlowType().isCall()){
                Function cal=getFunctionAt(ins.getFlows()[0]);
                if(cal!=null&&cal.isExternal()) continue;
            }
            for(var r: currentProgram.getReferenceManager().getReferencesTo(cur))
                if(r.getReferenceType().isFlow()) dq.add(r.getFromAddress());
        }
        Collections.reverse(chain); return chain;
    }

    /* CDFs */
    private void buildCDFs(){
        for(CallChain cc:ccs){
            Address sinkCall=cc.pcs().getLast();
            VD vd=vds.stream().filter(v->v.call().equals(sinkCall)).findFirst().orElse(null);
            if(vd==null) continue;
            for(Address pc:cc.pcs()){
                Instruction ins=getInstructionAt(pc);
                if(ins==null||!ins.getFlowType().isCall()) continue;
                Function cal=getFunctionAt(ins.getFlows()[0]);
                if(cal==null||!cal.isExternal()) continue;
                for(ExtParam src:sources) if(src.fn().equals(cal))
                    cdfs.add(new CDF(src,vd,cc));
            }
        }
        cdfs.removeIf(new HashSet<>()::add);
        println("  · CDFs = "+cdfs.size());
    }

    private String render(CDF c){
        return String.format("SRC %s p%d → SINK %s p%d (len=%d)",
                c.src().fn().getName(),c.src().idx(),
                c.dst().sink().fn().getName(),c.dst().sink().idx(),
                c.cc().pcs().size());
    }
}
