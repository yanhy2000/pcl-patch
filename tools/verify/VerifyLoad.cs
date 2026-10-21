using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;

// 对注入的方法做「真实 JIT 校验」：
// RuntimeHelpers.PrepareMethod 会强制 CLR 编译方法体，任何非法 IL
// （栈不平衡、分支越界、EH 结构错误）都会在这里抛出。
//
// 注意：不能用 Assembly.GetTypes()，PCL 的模块初始化器会在枚举时执行。
// 必须按名称取类型。
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("用法: VerifyLoad.exe <assembly> <Type::Method> ...");
            return 2;
        }

        var path = Path.GetFullPath(args[0]);
        Console.WriteLine("加载: " + path);

        Assembly asm;
        try
        {
            asm = Assembly.Load(File.ReadAllBytes(path));
        }
        catch (Exception ex)
        {
            Console.WriteLine("加载失败: " + ex.GetType().Name + ": " + ex.Message);
            return 1;
        }

        Console.WriteLine("程序集: " + asm.FullName);

        string[] targets;
        if (args.Length > 1)
        {
            targets = new string[args.Length - 1];
            Array.Copy(args, 1, targets, 0, targets.Length);
        }
        else
        {
            targets = new[] { "PCL.ModModpack::ModpackInstall" };
        }

        int fail = 0;
        int ok = 0;
        foreach (var t in targets)
        {
            string typeName = t;
            string methodName = null;
            int colon = t.IndexOf("::");
            if (colon > 0)
            {
                typeName = t.Substring(0, colon);
                methodName = t.Substring(colon + 2);
            }

            Type type;
            try
            {
                type = asm.GetType(typeName, false, false);
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [跳过] GetType(" + typeName + ") 失败: " + ex.GetType().Name);
                continue;
            }
            if (type == null)
            {
                Console.WriteLine("  [跳过] 找不到类型 " + typeName);
                continue;
            }

            MethodInfo[] methods;
            try
            {
                methods = type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic |
                                          BindingFlags.Static | BindingFlags.Instance |
                                          BindingFlags.DeclaredOnly);
            }
            catch (Exception ex)
            {
                Console.WriteLine("  [跳过] GetMethods 失败: " + ex.GetType().Name + ": " + ex.Message);
                continue;
            }

            foreach (var mi in methods)
            {
                if (methodName != null && mi.Name != methodName) continue;

                string sig = Describe(mi);
                try
                {
                    RuntimeHelpers.PrepareMethod(mi.MethodHandle);
                    Console.WriteLine("  [OK] " + sig);
                    ok++;
                }
                catch (Exception ex)
                {
                    fail++;
                    Console.WriteLine("  [FAIL] " + sig);
                    string msg;
                    try { msg = ex.GetType().Name + ": " + ex.Message; }
                    catch { msg = ex.GetType().Name; }
                    Console.WriteLine("         " + msg);
                }
            }
        }

        Console.WriteLine(string.Format("通过 {0} 个，失败 {1} 个", ok, fail));
        return fail == 0 ? 0 : 1;
    }

    private static string Describe(MethodInfo mi)
    {
        var ps = mi.GetParameters();
        var names = new string[ps.Length];
        for (int i = 0; i < ps.Length; i++) names[i] = ps[i].ParameterType.Name;
        return mi.DeclaringType.Name + "::" + mi.Name + "(" + string.Join(", ", names) + ")";
    }
}
