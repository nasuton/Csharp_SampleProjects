using Csharp_SampleProjects.AESEncrytDecry;

try
{
    // ここに実行したいコードを記載
    #region AES暗号化
    AESEncrytDecry.Main();
    #endregion
}
catch (Exception ex)
{
    Console.WriteLine(ex.ToString());
}

Console.WriteLine("\n終了するにはなにか押してください");
Console.ReadKey();