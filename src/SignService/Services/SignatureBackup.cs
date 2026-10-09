using System;
using System.IO;

namespace SignService.Services;

/// <summary>
/// Резервная копия файла подписи перед заменой без объединения или исключением
/// подписантов. Копия лежит рядом и не заканчивается на .sig, поэтому поиск
/// подписей её не подхватывает.
/// </summary>
internal static class SignatureBackup
{
    public static string Create(string path)
    {
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        var backup = path + "." + stamp + ".bak";
        for (var i = 1; File.Exists(backup); i++)
            backup = path + "." + stamp + "-" + i + ".bak";
        File.Copy(path, backup, overwrite: false);
        return backup;
    }
}
