using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;

// 用 CLR 自己的 JIT 来判定方法体是否合法。
//
// 关键点：RuntimeHelpers.PrepareMethod 会真正走一遍 JIT 的导入阶段，
// 只要 IL 结构非法（栈不平衡、分支落点不在指令边界、EH 区间重叠、
// 委托签名不匹配……）就会抛 InvalidProgramException —— 这正是补丁版
// 在用户机器上崩溃时看到的那个异常。
//
// 只 JIT 目标方法本身，不 JIT 它调用的方法，所以不需要 PCL 的运行时依赖
// 全部就位；WPF 类型在 .NET Framework 下由 GAC 提供。
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("用法: VerifyIL.exe <assembly> [Type::Method ...]");
            return 2;
        }

        var path = Path.GetFullPath(args[0]);
        Assembly asm;
        try
        {
            asm = Assembly.LoadFrom(path);
        }
        catch (Exception ex)
        {
            Console.WriteLine("加载失败: " + ex.GetType().Name + ": " + ex.Message);
            return 1;
        }

        // PCL2 把 MeloongCore 等依赖作为嵌入资源打包，运行时靠 AssemblyResolve 解析。
        // 这里照做，否则 JIT 目标方法时会因为找不到依赖而报 FileNotFoundException，
        // 掩盖掉真正想看的 InvalidProgramException。
        AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
        {
            string simple = new AssemblyName(e.Name).Name;
            foreach (var res in asm.GetManifestResourceNames())
            {
                if (!res.EndsWith(simple + ".dll", StringComparison.OrdinalIgnoreCase))
                    continue;
                using (var st = asm.GetManifestResourceStream(res))
                {
                    if (st == null) continue;
                    var buf = new byte[st.Length];
                    st.Read(buf, 0, buf.Length);
                    return Assembly.Load(buf);
                }
            }
            return null;
        };

        if (args.Length >= 2 && args[1] == "--list")
        {
            Console.WriteLine("嵌入资源：");
            foreach (var r in asm.GetManifestResourceNames())
                Console.WriteLine("  " + r);
            return 0;
        }

        // PCL2 把依赖程序集放进 ResourceManager 资源（PCL.Resources）里，
        // 由它自己的启动代码在 AssemblyResolve 时取出。这里照做，把依赖
        // 落盘到指定目录，方便后续独立 JIT 校验。
        if (args.Length >= 3 && args[1] == "--dumpdeps")
        {
            string dir = Path.GetFullPath(args[2]);
            Directory.CreateDirectory(dir);
            var rm = new System.Resources.ResourceManager("PCL.Resources", asm);
            var set = rm.GetResourceSet(System.Globalization.CultureInfo.InvariantCulture, true, true);
            int n = 0;
            foreach (System.Collections.DictionaryEntry e in set)
            {
                string key = e.Key.ToString();
                object val = e.Value;
                var bytes = val as byte[];
                Console.WriteLine(string.Format("  {0}  ({1}, {2})", key,
                    val == null ? "null" : val.GetType().Name,
                    bytes == null ? "-" : bytes.Length + " 字节"));
                if (bytes == null || bytes.Length < 1024) continue;
                string name = key;
                if (!name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    name = name + ".dll";
                File.WriteAllBytes(Path.Combine(dir, name), bytes);
                n++;
            }
            Console.WriteLine(string.Format("导出 {0} 个二进制资源", n));
            return 0;
        }

        string[] targets = new string[Math.Max(0, args.Length - 1)];
        if (targets.Length > 0)
        {
            Array.Copy(args, 1, targets, 0, targets.Length);
        }
        else
        {
            targets = new[]
            {
                "PCL.ModModpack::ModpackInstall",
                "PCL.PageDownloadResourceDetail::InitializeStackResourceVersions",
            };
        }

        int fail = 0, ok = 0;
        foreach (var t in targets)
        {
            string typeName = t, methodName = null;
            int c = t.IndexOf("::", StringComparison.Ordinal);
            if (c > 0) { typeName = t.Substring(0, c); methodName = t.Substring(c + 2); }

            Type type = asm.GetType(typeName, false, false);
            if (type == null)
            {
                Console.WriteLine("  [跳过] 找不到类型 " + typeName);
                continue;
            }

            foreach (var mi in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic |
                                               BindingFlags.Static | BindingFlags.Instance |
                                               BindingFlags.DeclaredOnly))
            {
                if (methodName != null && mi.Name != methodName) continue;

                string sig = Describe(mi);
                MethodBody mb;
                try
                {
                    mb = mi.GetMethodBody();
                }
                catch (Exception ex)
                {
                    fail++;
                    Console.WriteLine("  [FAIL] " + sig + " 读取方法体失败 -> "
                                      + ex.GetType().Name + ": " + ex.Message);
                    continue;
                }

                if (mb == null)
                {
                    Console.WriteLine("  [--] " + sig + "（无方法体）");
                    continue;
                }

                int ilLen = mb.GetILAsByteArray().Length;
                int locals = mb.LocalVariables == null ? 0 : mb.LocalVariables.Count;
                string detail = string.Format("IL={0}B maxStack={1} locals={2} EH={3}",
                                              ilLen, mb.MaxStackSize, locals,
                                              mb.ExceptionHandlingClauses.Count);

                try
                {
                    // 强制 JIT：这一步才是真正会抛 InvalidProgramException 的地方
                    RuntimeHelpers.PrepareMethod(mi.MethodHandle);
                    Console.WriteLine("  [OK] " + sig + "  " + detail);
                    ok++;
                }
                catch (Exception ex)
                {
                    fail++;
                    var inner = ex is TypeInitializationException && ex.InnerException != null
                                ? ex.InnerException : ex;
                    Console.WriteLine("  [FAIL] " + sig + "  " + detail);
                    Console.WriteLine("         -> " + inner.GetType().Name + ": " + inner.Message);
                }
            }
        }

        Console.WriteLine();
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
