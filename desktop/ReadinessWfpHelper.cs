using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;

// Inventory only: this intentionally does not infer a network verdict from filters.
public interface IReadOnlyWfpApi {
 uint Open(out IntPtr engine); uint Create(IntPtr engine,out IntPtr cursor);
 uint Next(IntPtr engine,IntPtr cursor,uint limit,out IntPtr entries,out uint count);
 void Free(ref IntPtr entries); uint Destroy(IntPtr engine,IntPtr cursor); uint Close(IntPtr engine);
}
public sealed class WindowsWfpApi:IReadOnlyWfpApi {
 [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)]static extern uint FwpmEngineOpen0(string serverName,uint authnService,IntPtr authIdentity,IntPtr session,out IntPtr engineHandle);
 [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterCreateEnumHandle0(IntPtr engineHandle,IntPtr enumTemplate,out IntPtr enumHandle);
 [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterEnum0(IntPtr engineHandle,IntPtr enumHandle,uint numEntriesRequested,out IntPtr entries,out uint numEntriesReturned);
 [DllImport("fwpuclnt.dll")]static extern void FwpmFreeMemory0(ref IntPtr p);
 [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle,IntPtr enumHandle);
 [DllImport("fwpuclnt.dll")]static extern uint FwpmEngineClose0(IntPtr engineHandle);
 public uint Open(out IntPtr engine){return FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine);}
 public uint Create(IntPtr engine,out IntPtr cursor){return FwpmFilterCreateEnumHandle0(engine,IntPtr.Zero,out cursor);}
 public uint Next(IntPtr engine,IntPtr cursor,uint limit,out IntPtr entries,out uint count){return FwpmFilterEnum0(engine,cursor,limit,out entries,out count);}
 public void Free(ref IntPtr entries){FwpmFreeMemory0(ref entries);}
 public uint Destroy(IntPtr engine,IntPtr cursor){return FwpmFilterDestroyEnumHandle0(engine,cursor);}
 public uint Close(IntPtr engine){return FwpmEngineClose0(engine);}
}
public sealed class WfpInventory {
 public string scope="read-only filter enumeration; not a policy audit",stage="not-started",reason="unverified",policyVerdict="unknown";
 public bool enumerationFinished,priorityVerified,coverageVerified,exceptionsVerified,dynamicLifecycleVerified,blockedConfirmed;
 public uint errorCode,cleanupError;public int returnedFilterCount,pages;
}
public static class ReadinessWfpHelper {
 public static WfpInventory Inspect(IReadOnlyWfpApi api,int maxPages,long maxMilliseconds){var result=new WfpInventory();IntPtr engine=IntPtr.Zero,cursor=IntPtr.Zero;var timer=Stopwatch.StartNew();try{result.stage="open";uint error=api.Open(out engine);if(error!=0||engine==IntPtr.Zero){result.errorCode=error;result.reason="engine-open-failed";return result;}result.stage="create-enumerator";error=api.Create(engine,out cursor);if(error!=0||cursor==IntPtr.Zero){result.errorCode=error;result.reason="enumerator-create-failed";return result;}result.stage="enumerate";for(int n=0;n<maxPages&&timer.ElapsedMilliseconds<maxMilliseconds;n++){IntPtr data=IntPtr.Zero;uint count=0;try{error=api.Next(engine,cursor,128,out data,out count);if(error!=0){result.errorCode=error;result.reason="enumeration-failed";return result;}if(count>128||count>0&&data==IntPtr.Zero){result.reason="invalid-api-result";return result;}result.pages++;result.returnedFilterCount+=(int)count;if(count<128){result.enumerationFinished=true;result.reason="filters-not-interpreted";return result;}}finally{if(data!=IntPtr.Zero)api.Free(ref data);}}result.reason=timer.ElapsedMilliseconds>=maxMilliseconds?"time-limit-between-calls":"page-limit";return result;}catch(Exception e){result.reason="api-exception-"+e.GetType().Name;return result;}finally{try{if(cursor!=IntPtr.Zero){uint e=api.Destroy(engine,cursor);if(e!=0)result.cleanupError=e;}}catch{result.reason="enumerator-cleanup-failed";}try{if(engine!=IntPtr.Zero){uint e=api.Close(engine);if(e!=0)result.cleanupError=e;}}catch{result.reason="engine-cleanup-failed";}result.stage="finished";}}
 public static int Main(string[] args){if(args.Length!=1){Console.Error.WriteLine("需要显式只读参数；不自动提权或修改策略。");return 2;}if(args[0]=="--read-only-wfp-observe"){var visible=ReadinessWfpNative.Observe(new VisibleWindowsWfpApi(),64,8000);Console.WriteLine(new JavaScriptSerializer().Serialize(visible));return visible.complete?0:1;}if(args[0]=="--read-only-wfp-inventory"){var result=Inspect(new WindowsWfpApi(),64,8000);Console.WriteLine(new JavaScriptSerializer().Serialize(result));return result.enumerationFinished&&result.cleanupError==0?0:1;}Console.Error.WriteLine("需要显式只读参数；不自动提权或修改策略。");return 2;}
}
