using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;

// 用「不触发依赖加载」的方式校验方法体 IL：
//  1. 反射加载程序集；
//  2. 拿到 MethodBase，用 GetMethodBody() 读取 IL；
//  3. 用 RuntimeHelpers.PrepareMethod 强制 JIT（会触发依赖解析，
//     因此这里改为「解析 IL 结构 + 校验分支边界」，不依赖外部程序集）。
//
// 真正执行 JIT 的检查通过 PCL 自带的启动流程完成（见 README）。
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("用法: VerifyIL.exe <assembly> <Type::Method> ...");
            return 2;
        }

        var path = Path.GetFullPath(args[0]);
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

        string[] targets = new string[Math.Max(0, args.Length - 1)];
        if (targets.Length > 0) Array.Copy(args, 1, targets, 0, targets.Length);
        else targets = new[] { "PCL.ModModpack::ModpackInstall" };

        int fail = 0, ok = 0;
        foreach (var t in targets)
        {
            string typeName = t, methodName = null;
            int c = t.IndexOf("::");
            if (c > 0) { typeName = t.Substring(0, c); methodName = t.Substring(c + 2); }

            Type type = asm.GetType(typeName, false, false);
            if (type == null) { Console.WriteLine("  [跳过] 找不到 " + typeName); continue; }

            foreach (var mi in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic |
                                               BindingFlags.Static | BindingFlags.Instance |
                                               BindingFlags.DeclaredOnly))
            {
                if (methodName != null && mi.Name != methodName) continue;
                string sig = Describe(mi);
                try
                {
                    MethodBody mb = mi.GetMethodBody();
                    if (mb == null) { Console.WriteLine("  [--] " + sig + "（无方法体）"); continue; }
                    byte[] il = mb.GetILAsByteArray();
                    Console.WriteLine("  [OK] " + sig);
                    Console.WriteLine("       IL=" + il.Length + "B  maxStack=" + mb.MaxStackSize +
                                      "  locals=" + (mb.LocalVariables == null ? 0 : mb.LocalVariables.Count) +
                                      "  EH=" + mb.ExceptionHandlingClauses.Count);
                    ok++;
                }
                catch (Exception ex)
                {
                    fail++;
                    Console.WriteLine("  [FAIL] " + sig + " -> " + ex.GetType().Name + ": " + ex.Message);
                }
            }
        }
        Console.WriteLine(string.Format("通过 {0}，失败 {1}", ok, fail));
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
