using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using System.Text;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace TestAesEncryption
{    
    public class AesEnDecryption
    {
        // Key with 256 and IV with 16 length
        private string AES_Key = "280f8bb8c43d532f389ef0e2a5321220b0782b065205dcdfcb8d8f02ed5115b9";
        private string AES_IV = "CC0A69779E15780ADAE46C45EB451A23";
        private string convertedKey = "KA+LuMQ9Uy84nvDipTISILB4KwZSBdzfy42PAu1RFbk=";
        private string convertedIV = "zAppd54VeAra5GxF60UaIw==";
        private IBuffer m_iv = null;
        private CryptographicKey m_key;

        public static string AesEncrypt(string data, string hexKey, string hexIv)
        {
            byte[] input = Encoding.ASCII.GetBytes(data);
            string base64Key = Convert.ToBase64String(ConvertFromStringToHex(hexKey)); // "KA+LuMQ9Uy84nvDipTISILB4KwZSBdzfy42PAu1RFbk="
            string base64IV = Convert.ToBase64String(ConvertFromStringToHex(hexIv));   // "zAppd54VeAra5GxF60UaIw==";

            IBuffer key = Convert.FromBase64String(base64Key).AsBuffer();
            IBuffer m_iv = Convert.FromBase64String(base64IV).AsBuffer();
            SymmetricKeyAlgorithmProvider provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            CryptographicKey m_key = provider.CreateSymmetricKey(key);

            IBuffer bufferMsg = CryptographicBuffer.ConvertStringToBinary(Encoding.ASCII.GetString(input), BinaryStringEncoding.Utf8);
            IBuffer bufferEncrypt = CryptographicEngine.Encrypt(m_key, bufferMsg, m_iv);
            byte[] encryptedBytes = bufferEncrypt.ToArray();

            string result = Convert.ToBase64String(encryptedBytes);
            return result;
        }

        public static byte[] ConvertFromStringToHex(string inputHex)
        {
            inputHex = inputHex.Replace("-", "");

            byte[] resultantArray = new byte[inputHex.Length / 2];
            for (int i = 0; i < resultantArray.Length; i++)
            {
                resultantArray[i] = Convert.ToByte(inputHex.Substring(i * 2, 2), 16);
            }
            return resultantArray;
        }

        public AesEnDecryption()
        {
            IBuffer key = Convert.FromBase64String(convertedKey).AsBuffer();
            m_iv = Convert.FromBase64String(convertedIV).AsBuffer();
            SymmetricKeyAlgorithmProvider provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            m_key = provider.CreateSymmetricKey(key);
        }

        public byte[] Encrypt(byte[] input)
        {
            IBuffer bufferMsg = CryptographicBuffer.ConvertStringToBinary(Encoding.ASCII.GetString(input), BinaryStringEncoding.Utf8);
            IBuffer bufferEncrypt = CryptographicEngine.Encrypt(m_key, bufferMsg, m_iv);
            return bufferEncrypt.ToArray();
        }

        public byte[] Decrypt(byte[] input)
        {
            IBuffer bufferDecrypt = CryptographicEngine.Decrypt(m_key, input.AsBuffer(), m_iv);
            return bufferDecrypt.ToArray();
        }
    }

    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            string originalText = OriginalTextTextBlock.Text;
            AesEnDecryption en = new AesEnDecryption();
            byte[] encryptedBytes = en.Encrypt(Encoding.ASCII.GetBytes(originalText));
            string uni = Convert.ToBase64String(encryptedBytes);
            EncryptedTextTextBlock.Text = AesEnDecryption.AesEncrypt(originalText, "280f8bb8c43d532f389ef0e2a5321220b0782b065205dcdfcb8d8f02ed5115b9", "CC0A69779E15780ADAE46C45EB451A23");
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {

        }
    }
}
