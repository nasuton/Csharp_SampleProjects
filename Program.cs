using Csharp_SampleProjects.AESEncrytDecry;

try
{
    // ここに実行したいコードを記載
    #region AES暗号化
    string key = @"Testhoge0808080808080808";
    string iv = @"HugaPiyo08080808";
    string plainText = @"吾輩は猫であるまだ名前はない";
    Console.WriteLine($"元の文字列：{plainText}");
    var aes = new AESEncrytDecry(key, iv, AESType.AES_192);
    var cipherText = aes.EncryptStringAES(plainText);
    Console.WriteLine($"暗号化された文字列：{cipherText}");
    plainText = aes.DecryptStringAES(cipherText);
    Console.WriteLine($"復号化された文字列：{plainText}");
    #endregion
}
catch (Exception ex)
{
    Console.WriteLine(ex.ToString());
}

Console.WriteLine("\n終了するにはなにか押してください");
Console.ReadKey();