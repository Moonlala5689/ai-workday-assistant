using System;


public sealed class WfpVisibleSnapshot {
 public bool complete,conditionsOpaque,contextOpaque,weightsComplete=true,subLayersComplete=true;
 public int count,active,disabled,block,permit,callout,other,conditional,conditionCount,conditionKinds,matchKinds,subLayerUnknown,weightUnknown,pages,persistent,bootTime,clearAction,weightKnown,subLayerKnown;
 public ulong weightMin,weightMax;public ushort subLayerMin,subLayerMax;
 public uint errorCode;public long capturedTicks;public string reason="unavailable",fingerprint="";
}
